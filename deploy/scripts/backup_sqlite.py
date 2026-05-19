from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def backup_sqlite(source: Path, destination_dir: Path) -> Path:
    if not source.exists():
        raise FileNotFoundError(f"SQLite database does not exist: {source}")
    if not source.is_file():
        raise ValueError(f"SQLite source is not a file: {source}")

    destination_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    destination = destination_dir / f"{source.stem}-{stamp}{source.suffix}"

    with sqlite3.connect(source) as src, sqlite3.connect(destination) as dst:
        src.backup(dst)

    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a safe SQLite backup.")
    parser.add_argument("source", type=Path, help="Path to the SQLite database file.")
    parser.add_argument("destination_dir", type=Path, help="Directory to write the backup file.")
    args = parser.parse_args()

    destination = backup_sqlite(args.source, args.destination_dir)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
