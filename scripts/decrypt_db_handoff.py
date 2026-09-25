"""Decrypt the GitHub-delivered Batuhan database handoff bundle."""
from __future__ import annotations

import argparse
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True, help="Fernet key received outside GitHub")
    parser.add_argument(
        "--input", default="handoff/agentguard-batuhan.bundle",
        help="Encrypted bundle downloaded from GitHub",
    )
    parser.add_argument("--output", default="BATUHAN_DB_HANDOFF.zip")
    args = parser.parse_args()
    try:
        clear = Fernet(args.key.encode()).decrypt(Path(args.input).read_bytes())
    except InvalidToken:
        raise SystemExit("DECRYPTION_FAILED: wrong key or damaged bundle")
    Path(args.output).write_bytes(clear)
    print(f"Decrypted handoff: {Path(args.output).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
