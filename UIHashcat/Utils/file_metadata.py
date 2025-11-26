import json
import os
from typing import Dict, Optional

from django.conf import settings

DEFAULT_META_PATHS = {
    "wordlists": os.path.join(os.path.dirname(__file__), "..", "Files", "Wordlistfiles", ".metadata.json"),
    "rules": os.path.join(os.path.dirname(__file__), "..", "Files", "Rulefiles", ".metadata.json"),
    "masks": os.path.join(os.path.dirname(__file__), "..", "Files", "Maskfiles", ".metadata.json"),
}


def _meta_path(category: str) -> str:
    override = getattr(settings, "HASHCAT_METADATA_PATHS", {})
    return override.get(category, DEFAULT_META_PATHS[category])


def load_metadata(category: str) -> Dict[str, Dict[str, Optional[int]]]:
    path = _meta_path(category)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def save_metadata(category: str, meta: Dict[str, Dict[str, Optional[int]]]) -> None:
    path = _meta_path(category)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(meta, handle)


def update_entry(category: str, name: str, md5: Optional[str], lines: Optional[int]) -> None:
    meta = load_metadata(category)
    meta[name] = {"md5": md5, "lines": lines}
    save_metadata(category, meta)


def remove_entry(category: str, name: str) -> None:
    meta = load_metadata(category)
    if name in meta:
        del meta[name]
        save_metadata(category, meta)
