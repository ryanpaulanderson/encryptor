#!/usr/bin/env python3
"""Fail closed when dependency evidence is stale or does not match inputs."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
import os
import sys


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_security_evidence.py EVIDENCE.json")
    evidence = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    if evidence.get("documentType") != "encryptor.dependency-intelligence":
        raise SystemExit("unexpected evidence type")
    if evidence.get("registryRefresh") != "succeeded":
        raise SystemExit("registry refresh did not succeed")
    expected_commit = os.environ.get("GITHUB_SHA")
    if expected_commit is not None and evidence.get("sourceCommit") != expected_commit:
        raise SystemExit("dependency evidence source commit mismatch")
    now = dt.datetime.now(dt.timezone.utc)
    generated = utc(evidence["generatedAt"])
    expires = utc(evidence["expiresAt"])
    if not generated <= now <= expires:
        raise SystemExit("dependency evidence is not currently valid")
    if expires - generated > dt.timedelta(days=7):
        raise SystemExit("dependency evidence lifetime exceeds seven days")
    expected = {
        "Cargo.lock": sha256(pathlib.Path("Cargo.lock")),
        "fuzz/Cargo.lock": sha256(pathlib.Path("fuzz/Cargo.lock")),
    }
    if evidence.get("lockfiles") != expected:
        raise SystemExit("lockfile digest mismatch")
    if evidence.get("policy", {}).get("deny.toml") != sha256(pathlib.Path("deny.toml")):
        raise SystemExit("dependency policy digest mismatch")
    scanners = evidence.get("scanners", {})
    required_scanner_fields = {
        "cargoAudit",
        "cargoDeny",
        "cargoAuditSha256",
        "cargoDenySha256",
        "rustSecAdvisoryDatabaseRevision",
        "rustSecAdvisoryDatabaseRevisionTime",
    }
    if not required_scanner_fields.issubset(scanners):
        raise SystemExit("dependency evidence is missing scanner provenance")
    for field in ("cargoAuditSha256", "cargoDenySha256"):
        value = scanners[field]
        if not isinstance(value, str) or len(value) != 64:
            raise SystemExit(f"dependency evidence has invalid {field}")
        try:
            int(value, 16)
        except ValueError as error:
            raise SystemExit(f"dependency evidence has invalid {field}") from error
    revision = scanners["rustSecAdvisoryDatabaseRevision"]
    if not isinstance(revision, str) or len(revision) not in (40, 64):
        raise SystemExit("dependency evidence has invalid RustSec revision")
    try:
        int(revision, 16)
    except ValueError as error:
        raise SystemExit("dependency evidence has invalid RustSec revision") from error
    utc(scanners["rustSecAdvisoryDatabaseRevisionTime"])


if __name__ == "__main__":
    main()
