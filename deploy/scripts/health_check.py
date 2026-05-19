from __future__ import annotations

import argparse
import json
import sys
from urllib.request import Request, urlopen


def check_health(base_url: str, timeout: int = 10) -> dict:
    url = base_url.rstrip("/") + "/api/health"
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
        if response.status != 200 or body.get("ok") is not True:
            raise RuntimeError(f"Unhealthy response from {url}: {body}")
        return body


def main() -> int:
    parser = argparse.ArgumentParser(description="Check license panel health endpoint.")
    parser.add_argument("base_url", nargs="?", default="http://127.0.0.1:5055")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    try:
        body = check_health(args.base_url, timeout=args.timeout)
    except Exception as exc:
        print(f"health check failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(body, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
