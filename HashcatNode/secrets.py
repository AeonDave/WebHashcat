import hashlib
import os
from typing import Optional, Tuple


def read_secret(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value.strip() if value else None


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def resolve_credentials(server_config=None, allow_password_and_hash: bool = False) -> Tuple[str, str]:
    server_section = server_config or {}
    username = read_secret("HASHCATNODE_USERNAME") or server_section.get("username", "").strip()
    if not username:
        raise RuntimeError("HASHCAT node username is not configured via environment variables")

    password = read_secret("HASHCATNODE_PASSWORD")
    password_hash = read_secret("HASHCATNODE_HASH") or server_section.get("sha256hash", "").strip()

    if password and password_hash and not (
            allow_password_and_hash or os.environ.get("HASHCATNODE_ALLOW_PASSWORD_AND_HASH")):
        raise RuntimeError("Provide either HASHCATNODE_PASSWORD or HASHCATNODE_HASH, not both")

    if password:
        password_hash = hash_password(password)

    if not password_hash:
        raise RuntimeError("HASHCAT node password/hash is not configured")

    return username, password_hash
