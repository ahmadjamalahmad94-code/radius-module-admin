"""Enable ``python -m fleet.health.monitor`` (and ``python -m fleet.health``).

This shim exists so cron / systemd timers can call the monitor without
having to know the function name. The actual logic lives in
:mod:`fleet.health.monitor`.
"""
from fleet.health.monitor import _cli

if __name__ == "__main__":  # pragma: no cover - thin shim
    raise SystemExit(_cli())
