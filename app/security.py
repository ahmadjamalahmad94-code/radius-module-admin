from __future__ import annotations

from flask import request


def client_ip(trust_proxy_headers: bool) -> str:
    if trust_proxy_headers:
        forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.remote_addr or "unknown"


def clean_text(value, max_length: int) -> str:
    text = str(value or "").strip()
    if len(text) > max_length:
        raise ValueError(f"Value exceeds {max_length} characters.")
    return text
