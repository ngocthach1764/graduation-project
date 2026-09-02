#!/usr/bin/env python3
"""Write a small, portable provenance manifest for one experiment directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def git(*args: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", *args], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def digest(path: Path) -> dict[str, object]:
    item: dict[str, object] = {"path": str(path)}
    if not path.is_file():
        item["missing"] = True
        return item
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    item.update({"bytes": path.stat().st_size, "sha256": h.hexdigest()})
    return item


def key_values(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"parameter must be key=value: {value}")
        key, raw = value.split("=", 1)
        parsed[key] = raw
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--command", action="append", default=[])
    parser.add_argument("--parameter", action="append", default=[])
    parser.add_argument("--artifact", action="append", default=[])
    args = parser.parse_args()

    status = git("status", "--porcelain")
    manifest = {
        "schema": "scada_experiment_manifest_v1",
        "suite": args.suite,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "working_directory": str(Path.cwd().resolve()),
        "git": {
            "commit": git("rev-parse", "HEAD"),
            "branch": git("branch", "--show-current"),
            "dirty": None if status is None else bool(status),
        },
        "runtime": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "parameters": key_values(args.parameter),
        "commands": args.command,
        "artifacts": [digest(Path(item)) for item in args.artifact],
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
