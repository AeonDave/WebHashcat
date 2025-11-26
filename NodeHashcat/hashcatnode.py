#!/usr/bin/python3
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

try:  # Allow running as a module or standalone script
    from .httpapi import Server  # type: ignore
    from .hashcat import Hashcat  # type: ignore
    from . import secrets as node_secrets  # type: ignore
except ImportError:  # pragma: no cover - fallback for direct execution
    from httpapi import Server
    from hashcat import Hashcat
    import secrets as node_secrets  # type: ignore

BASE_DIR = Path(__file__).resolve().parent


def _env(name: str, default: str | None = None, *, required: bool = False) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        if required:
            raise RuntimeError(f"Missing required environment variable {name}")
        return default
    return value


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return str(value).lower() in {"1", "true", "yes", "on"}


DEFAULT_CERT_SUBJECT = _env(
    "HASHCATNODE_TLS_SUBJECT",
    "/C=IT/ST=Italy/L=Turin/O=WebHashcat/OU=HashcatNode/CN=hashcatnode",
)


@dataclass
class NodeSettings:
    bind_address: str
    bind_port: int
    username: str
    password_hash: str
    binary: str
    hashes_dir: str
    rules_dir: str
    mask_dir: str
    wordlist_dir: str
    workload_profile: str
    cert_file: str
    key_file: str
    brain_enabled: str
    brain_host: str
    brain_port: str
    brain_password: str

    def apply_to_hashcat(self) -> None:
        Hashcat.binary = self.binary
        Hashcat.rules_dir = self.rules_dir
        Hashcat.wordlist_dir = self.wordlist_dir
        Hashcat.mask_dir = self.mask_dir
        Hashcat.hash_dir = self.hashes_dir
        Hashcat.workload_profile = self.workload_profile
        Hashcat.brain = {
            'enabled': self.brain_enabled,
            'host': self.brain_host,
            'port': self.brain_port,
            'password': self.brain_password,
        }


def _directory_from_env(env_name: str, fallback: str) -> str:
    raw_value = os.environ.get(env_name, fallback)
    if not raw_value:
        raise RuntimeError(f"Missing configuration for directory {env_name}")
    path = Path(raw_value).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _ensure_tls_material(cert_path: Path, key_path: Path) -> Tuple[str, str]:
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    logging.info("Generating self-signed TLS certificate at %s", cert_path)
    days = os.environ.get("HASHCATNODE_TLS_DAYS", "365")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            str(days),
            "-nodes",
            "-subj",
            DEFAULT_CERT_SUBJECT,
        ],
        check=True,
    )
    os.chmod(key_path, 0o600)
    return str(cert_path), str(key_path)


def _configure_logging(loglevel_str: str) -> None:
    loglevel_dict = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }

    logfile = BASE_DIR / "hashcatnode.log"

    logging.basicConfig(
        filename=str(logfile),
        format='%(asctime)s\t%(levelname)s\t%(message)s',
        level=loglevel_dict.get(loglevel_str.lower(), logging.INFO),
    )


def _load_directories() -> Tuple[str, str, str, str]:
    hashes_dir = _directory_from_env("HASHCATNODE_HASHES_DIR", "/hashcatnode/hashes")
    rules_dir = _directory_from_env("HASHCATNODE_RULES_DIR", "/hashcatnode/rules")
    mask_dir = _directory_from_env("HASHCATNODE_MASKS_DIR", "/hashcatnode/masks")
    wordlist_dir = _directory_from_env("HASHCATNODE_WORDLISTS_DIR", "/hashcatnode/wordlists")
    return hashes_dir, rules_dir, mask_dir, wordlist_dir


def _build_settings() -> NodeSettings:
    bind_address = _env("HASHCATNODE_BIND", "0.0.0.0")
    bind_port = int(_env("HASHCATNODE_PORT", "9999"))
    username, username_hash = node_secrets.resolve_credentials()

    binary = _env("HASHCATNODE_BINARY", "/usr/local/bin/hashcat")
    hashes_dir, rules_dir, mask_dir, wordlist_dir = _load_directories()
    workload_profile = _env("HASHCATNODE_WORKLOAD_PROFILE", "3")

    cert_dir_default = _env("HASHCATNODE_CERT_DIR", str(BASE_DIR / "certs"))
    cert_dir = Path(cert_dir_default)
    cert_path = Path(_env("HASHCATNODE_CERT_PATH", str(cert_dir / "server.crt")))
    key_path = Path(_env("HASHCATNODE_KEY_PATH", str(cert_dir / "server.key")))
    cert_file, key_file = _ensure_tls_material(cert_path, key_path)

    brain_enabled = "true" if _bool_env("HASHCATNODE_BRAIN_ENABLED", False) else "false"
    brain_host = (_env("HASHCATNODE_BRAIN_HOST", _env("HASHCAT_BRAIN_HOST", "")) or "").strip()
    brain_port = _env("HASHCATNODE_BRAIN_PORT", _env("HASHCAT_BRAIN_PORT", "13743"))
    brain_password = _env("HASHCATNODE_BRAIN_PASSWORD", _env("HASHCAT_BRAIN_PASSWORD", ""))

    if brain_enabled == "true" and not brain_password:
        raise RuntimeError("Brain is enabled but HASHCATNODE_BRAIN_PASSWORD/HASHCAT_BRAIN_PASSWORD is not set")

    return NodeSettings(
        bind_address=bind_address,
        bind_port=bind_port,
        username=username,
        password_hash=username_hash,
        binary=binary,
        hashes_dir=hashes_dir,
        rules_dir=rules_dir,
        mask_dir=mask_dir,
        wordlist_dir=wordlist_dir,
        workload_profile=workload_profile,
        cert_file=cert_file,
        key_file=key_file,
        brain_enabled=brain_enabled,
        # ``host`` is optional; when omitted the node can auto-detect it
        # from incoming WebHashcat requests.
        brain_host=brain_host,
        brain_port=brain_port,
        brain_password=brain_password,
    )


def _detect_device_type() -> int:
    """Return preferred hashcat device type for this node (1 CPU, 2 GPU, 3 other)."""
    env_value = os.environ.get("HASHCATNODE_DEVICE_TYPE")
    if env_value and env_value.isdigit() and env_value in {"1", "2", "3"}:
        return int(env_value)

    # Heuristic: if GPU devices are exposed, prefer GPU, else default to CPU.
    nvidia_devices = os.environ.get("NVIDIA_VISIBLE_DEVICES")
    if nvidia_devices and nvidia_devices.lower() not in {"", "none"}:
        return 2
    if os.path.exists("/dev/nvidia0"):
        return 2
    return 1


def main(run_server: bool = True):
    loglevel_str = _env("HASHCATNODE_LOGLEVEL", "info")
    _configure_logging(loglevel_str)

    settings = _build_settings()

    logging.info("Hashcat node starting on %s:%s (db=%s)", settings.bind_address, settings.bind_port,
                 os.environ.get("HASHCATNODE_DB_PATH", "hashcatnode.db"))

    settings.apply_to_hashcat()
    Hashcat.default_device_type = _detect_device_type()

    Hashcat.parse_version()
    Hashcat.parse_help()
    Hashcat.parse_rules()
    Hashcat.parse_masks()
    Hashcat.parse_wordlists()

    Hashcat.reload_sessions()

    if run_server:
        https_server = Server(
            settings.bind_address,
            settings.bind_port,
            settings.username,
            settings.password_hash,
            settings.hashes_dir,
            settings.cert_file,
            settings.key_file,
        )
        https_server.start_server()

    return Hashcat


if __name__ == "__main__":
    main()
