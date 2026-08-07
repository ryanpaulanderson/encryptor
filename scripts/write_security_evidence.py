#!/usr/bin/env python3
"""Write digest-bound, short-lived dependency intelligence evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import shutil
import subprocess


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(*arguments: str) -> str:
    return subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    ).stdout.strip()


def command_path(name: str) -> pathlib.Path:
    resolved = shutil.which(name)
    if resolved is None:
        raise SystemExit(f"required command is not installed: {name}")
    return pathlib.Path(resolved)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--expires-days", type=int, default=7)
    args = parser.parse_args()
    if not 1 <= args.expires_days <= 7:
        raise SystemExit("evidence expiry must be between one and seven days")

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    cargo_home = pathlib.Path(os.environ.get("CARGO_HOME", pathlib.Path.home() / ".cargo"))
    advisory_db = cargo_home / "advisory-db"
    advisory_revision = command("git", "-C", str(advisory_db), "rev-parse", "HEAD")
    advisory_revision_time = command(
        "git", "-C", str(advisory_db), "show", "-s", "--format=%cI", "HEAD"
    )
    evidence = {
        "documentType": "encryptor.dependency-intelligence",
        "schemaVersion": 1,
        "sourceCommit": os.environ.get("GITHUB_SHA", command("git", "rev-parse", "HEAD")),
        "generatedAt": now.isoformat().replace("+00:00", "Z"),
        "expiresAt": (now + dt.timedelta(days=args.expires_days))
        .isoformat()
        .replace("+00:00", "Z"),
        "registryRefresh": "succeeded",
        "lockfiles": {
            "Cargo.lock": sha256(pathlib.Path("Cargo.lock")),
            "fuzz/Cargo.lock": sha256(pathlib.Path("fuzz/Cargo.lock")),
        },
        "policy": {"deny.toml": sha256(pathlib.Path("deny.toml"))},
        "scanners": {
            "cargoAudit": command("cargo", "audit", "--version"),
            "cargoDeny": command("cargo", "deny", "--version"),
            "cargoAuditSha256": sha256(command_path("cargo-audit")),
            "cargoDenySha256": sha256(command_path("cargo-deny")),
            "rustSecAdvisoryDatabaseRevision": advisory_revision,
            "rustSecAdvisoryDatabaseRevisionTime": advisory_revision_time,
        },
    }
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
