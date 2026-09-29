"""Generate one offline credential entry for the proxy's ``auth.users`` map."""
from __future__ import annotations

import argparse
import getpass
import json
import secrets
import sys
from typing import Sequence

from .auth import hash_password

_SALT_LENGTH = 16


def derive_password_hash(password: str, salt: bytes) -> bytes:
    """Derive the proxy authentication key from a plaintext password."""
    if len(salt) != _SALT_LENGTH:
        raise ValueError("salt must be exactly 16 bytes")
    return hash_password(password.encode("utf-8"), salt)


def generate_credentials(password: str) -> dict[str, str]:
    """Generate a fresh salted proxy credential."""
    salt = secrets.token_bytes(_SALT_LENGTH)
    return {"salt": salt.hex(), "hash": derive_password_hash(password, salt).hex()}


def validate_username(name: str) -> None:
    """Reject usernames that cannot safely identify a Basic-auth user."""
    if not 1 <= len(name) <= 64:
        raise ValueError("username must be 1 to 64 characters")
    if ":" in name:
        raise ValueError("username must not contain ':'")
    if any(character.isspace() for character in name):
        raise ValueError("username must not contain spaces")
    if any(
        ord(character) < 32 or 0x7F <= ord(character) <= 0x9F
        for character in name
    ):
        raise ValueError("username must not contain control characters")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a salted credential entry for proxy authentication."
    )
    parser.add_argument("name", help="username to add to auth.users")
    return parser


def _entry_json(name: str, credentials: dict[str, str]) -> str:
    """Serialize one JSON object member without its surrounding braces."""
    encoded = json.dumps({name: credentials}, ensure_ascii=True, separators=(",", ":"))
    return encoded[1:-1]


def main(
    argv: Sequence[str] | None = None,
    prompt=getpass.getpass,
    out=sys.stdout,
) -> int:
    """Run the credential-generation command and return its process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        validate_username(args.name)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    try:
        password = prompt("Password: ")
        confirmation = prompt("Repeat: ")
    except (EOFError, OSError, KeyboardInterrupt):
        print("error: unable to read password", file=sys.stderr)
        return 2

    if password != confirmation:
        print("error: passwords do not match", file=sys.stderr)
        return 2
    if not password:
        print("error: password must not be empty", file=sys.stderr)
        return 2

    try:
        credentials = generate_credentials(password)
    except (KeyboardInterrupt, MemoryError, TypeError, ValueError, OSError):
        print("error: unable to generate credentials", file=sys.stderr)
        return 1

    print(_entry_json(args.name, credentials), file=out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
