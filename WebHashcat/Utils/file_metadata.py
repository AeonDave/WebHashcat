import json
import os
from typing import Dict, Optional

from django.conf import settings

DEFAULT_META_PATH = os.path.join(os.path.dirname(__file__), "..", "Files", "Wordlistfiles", ".metadata.json")


def _meta_path() -> str:
    return getattr(settings, "HASHCAT_WORDLIST_META_PATH", DEFAULT_META_PATH)


def load_metadata() -> Dict[str, Dict[str, Optional[int]]]:
    path = _meta_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def save_metadata(meta: Dict[str, Dict[str, Optional[int]]]) -> None:
    path = _meta_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(meta, handle)


def update_entry(name: str, md5: str, lines: Optional[int]) -> None:
    meta = load_metadata()
    meta[name] = {"md5": md5, "lines": lines}
    save_metadata(meta)


def remove_entry(name: str) -> None:
    meta = load_metadata()
    if name in meta:
        del meta[name]
        save_metadata(meta)
