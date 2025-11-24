import hashlib
import os
from typing import Optional, Tuple


def read_secret(name: str) -> Optional[str]:
    file_key = f"{name}_FILE"
    file_path = os.environ.get(file_key)
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError as exc:
            raise RuntimeError(f"Unable to read secret file {file_path}: {exc}") from exc
    value = os.environ.get(name)
    return value.strip() if value else None


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def resolve_credentials(server_config, allow_password_and_hash: bool = False) -> Tuple[str, str]:
    username = read_secret("HASHCATNODE_USERNAME") or server_config.get("username", "").strip()
    if not username:
        raise RuntimeError("HASHCAT node username is not configured via env or settings.ini")

    password = read_secret("HASHCATNODE_PASSWORD")
    password_hash = read_secret("HASHCATNODE_HASH") or server_config.get("sha256hash", "").strip()

    if password and password_hash and not (
            allow_password_and_hash or os.environ.get("HASHCATNODE_ALLOW_PASSWORD_AND_HASH")):
        raise RuntimeError("Provide either HASHCATNODE_PASSWORD or HASHCATNODE_HASH, not both")

    if password:
        password_hash = hash_password(password)

    if not password_hash:
        raise RuntimeError("HASHCAT node password/hash is not configured")

    return username, password_hash
