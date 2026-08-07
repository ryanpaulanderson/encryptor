#!/usr/bin/env python3
"""Exercise the exact release binary through its headless password prompts."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile


def run_prompted(command: list[str], prompts: list[bytes], response: bytes) -> bytes:
    completed = subprocess.run(
        command,
        input=b"".join(response + b"\n" for _ in prompts),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError("release binary returned a failure status")
    offset = 0
    for prompt in prompts:
        position = completed.stdout.find(prompt, offset)
        if position < 0:
            raise RuntimeError("release binary did not issue the expected prompts")
        offset = position + len(prompt)
    return completed.stdout


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: release_e2e.py BINARY EXPECTED_VERSION")
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    version = subprocess.run(
        [binary, "--version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if version != f"chacha20_poly1305 {sys.argv[2]}":
        raise SystemExit(f"unexpected release version: {version!r}")

    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "source.bin"
        encrypted = root / "encrypted.cpv2"
        recovered = root / "recovered.bin"
        payload = bytes(range(256)) * 8193
        source.write_bytes(payload)
        password = b"release-e2e-password"
        run_prompted(
            [binary, "encrypt", str(source), str(encrypted)],
            [b"File password: ", b"Confirm file password: "],
            password,
        )
        run_prompted(
            [binary, "decrypt", str(encrypted), str(recovered)],
            [b"File password: "],
            password,
        )
        if recovered.read_bytes() != payload:
            raise SystemExit("release binary round trip changed the payload")


if __name__ == "__main__":
    main()
