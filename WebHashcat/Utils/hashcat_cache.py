import json
import time
from typing import Any, Dict, Optional

import redis
from django.conf import settings

DEFAULT_CACHE_KEY = getattr(settings, "HASHCAT_CACHE_KEY", "webhashcat:hashcat-snapshot")
DEFAULT_CACHE_URL = getattr(
    settings,
    "HASHCAT_CACHE_REDIS_URL",
    getattr(settings, "CELERY_BROKER_URL", "redis://localhost:6379/1"),
)
DEFAULT_CACHE_TTL_SECONDS = getattr(settings, "HASHCAT_CACHE_TTL_SECONDS", 300)
DEFAULT_CACHE_STALE_SECONDS = getattr(settings, "HASHCAT_CACHE_STALE_SECONDS", 90)


class HashcatSnapshotCache:
    """Helper to persist node and session snapshots in Redis."""

    def __init__(self, cache_key: Optional[str] = None):
        self.cache_key = cache_key or DEFAULT_CACHE_KEY
        self._client = redis.Redis.from_url(DEFAULT_CACHE_URL, decode_responses=True)
        self._ttl = DEFAULT_CACHE_TTL_SECONDS
        self._stale_after = DEFAULT_CACHE_STALE_SECONDS

    def store_snapshot(self, snapshot: Dict[str, Any]) -> None:
        payload = json.dumps(snapshot)
        if self._ttl:
            self._client.setex(self.cache_key, self._ttl, payload)
        else:
            self._client.set(self.cache_key, payload)

    def get_snapshot(self) -> Optional[Dict[str, Any]]:
        payload = self._client.get(self.cache_key)
        if not payload:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def get_node_snapshot(self, node_id: int, snapshot: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        snapshot = snapshot or self.get_snapshot()
        if not snapshot:
            return None
        return snapshot.get("nodes", {}).get(str(node_id))

    def get_session_snapshot(self, session_name: str, snapshot: Optional[Dict[str, Any]] = None) -> Optional[
        Dict[str, Any]]:
        snapshot = snapshot or self.get_snapshot()
        if not snapshot:
            return None
        return snapshot.get("sessions", {}).get(session_name)

    def get_metadata(self, snapshot: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        meta = {
            "cache_key": self.cache_key,
            "stale_after_seconds": self._stale_after,
        }
        if not snapshot:
            meta.update(
                {
                    "available": False,
                    "generated_at": None,
                    "age_seconds": None,
                    "is_stale": True,
                }
            )
            return meta

        generated_epoch = snapshot.get("generated_at_epoch")
        age_seconds: Optional[float]
        if generated_epoch is None:
            age_seconds = None
            is_stale = True
        else:
            age_seconds = max(0.0, time.time() - float(generated_epoch))
            is_stale = age_seconds > self._stale_after

        meta.update(
            {
                "available": True,
                "generated_at": snapshot.get("generated_at"),
                "age_seconds": age_seconds,
                "is_stale": is_stale,
            }
        )
        return meta


__all__ = ["HashcatSnapshotCache"]
