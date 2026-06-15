"""Tests for the generated cloud-init user-data (deploy/accel-ppp/cloud-init.yaml).

No PyYAML in this project, so we validate the cloud-config structurally (it's
deliberately simple: base64 single-line content blobs) and prove it has not
drifted from the canonical source files by:
  1. asserting build_cloud_init.render() == the committed file (exact), and
  2. base64-decoding each embedded blob and comparing to its source file.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[1] / "deploy" / "accel-ppp"
if str(DEPLOY) not in sys.path:
    sys.path.insert(0, str(DEPLOY))

import build_cloud_init as bci  # noqa: E402

CLOUD_INIT = DEPLOY / "cloud-init.yaml"


def _text() -> str:
    return CLOUD_INIT.read_text(encoding="utf-8")


def test_committed_file_matches_generator():
    # Drift guard: editing any source file (script/template/agent) without
    # regenerating cloud-init.yaml fails here.
    assert _text() == bci.render(), (
        "cloud-init.yaml is stale — run: "
        "python3 deploy/accel-ppp/build_cloud_init.py > deploy/accel-ppp/cloud-init.yaml"
    )


def test_is_cloud_config_and_ascii():
    text = _text()
    assert text.splitlines()[0] == "#cloud-config"   # cloud-init requires this marker
    assert text.isascii()                            # base64 blobs keep it ASCII
    assert "\t" not in text                          # YAML forbids tabs for indentation


def test_has_write_files_and_runcmd_referencing_script():
    text = _text()
    assert "\nwrite_files:\n" in text
    assert "\nruncmd:\n" in text
    # runcmd actually runs the activation script.
    assert "setup-radius-vps.sh" in text
    assert "accel-activation.env" in text  # sources the operator-edited env first


def test_set_me_variables_present_plaintext():
    text = _text()
    # The operator-edited block is plaintext (not base64) so it can be filled in.
    for key in ("VPS_IP=", "SUBDOMAIN=", "RADIUS_SECRET=", "CERTBOT_EMAIL="):
        assert key in text
    assert ">>> SET ME" in text


def _embedded_blobs(text: str) -> dict[str, str]:
    """Map each write_files dest path → its base64 content line."""
    out: dict[str, str] = {}
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("- path:"):
            dest = s.split("- path:", 1)[1].strip()
            # find the content: line within this item's block
            for j in range(i + 1, min(i + 6, len(lines))):
                cs = lines[j].strip()
                if cs.startswith("content:") and "encoding: b64" in "\n".join(lines[i:j + 1]):
                    out[dest] = cs.split("content:", 1)[1].strip()
                    break
    return out


def test_embedded_blobs_decode_to_sources():
    text = _text()
    blobs = _embedded_blobs(text)
    # Each embedded file's base64 must decode byte-for-byte to its source.
    expected = {
        "/opt/hoberadius/accel-ppp/setup-radius-vps.sh": DEPLOY / "setup-radius-vps.sh",
        "/opt/hoberadius/accel-ppp/accel-ppp.conf.tmpl": DEPLOY / "accel-ppp.conf.tmpl",
        "/opt/hoberadius/accel-ppp/agent/vps_agent.py": DEPLOY / "agent" / "vps_agent.py",
        "/opt/hoberadius/accel-ppp/agent/__init__.py": DEPLOY / "agent" / "__init__.py",
    }
    for dest, src in expected.items():
        assert dest in blobs, f"missing embedded file {dest}"
        decoded = base64.b64decode(blobs[dest])
        assert decoded == src.read_bytes(), f"embedded {dest} differs from {src}"


def test_runcmd_sources_env_before_running_script():
    # Order matters: the env (with the SET ME vars) must be sourced before the
    # script runs, else VPS_IP/SUBDOMAIN/RADIUS_SECRET are empty and it aborts.
    text = _text()
    runcmd_line = next(ln for ln in text.splitlines() if "setup-radius-vps.sh" in ln and "bash" in ln)
    env_pos = runcmd_line.find("accel-activation.env")
    script_pos = runcmd_line.find("setup-radius-vps.sh")
    assert 0 < env_pos < script_pos
