from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NodeSnapshot:
    id: int
    name: str
    hostname: str
    port: int
    status: str = "Error"
    version: Optional[str] = None
    error: Optional[str] = None
    fetched_at: Optional[str] = None
    sessions: List[Dict[str, Any]] = field(default_factory=list)
    session_count: int = 0
    running_sessions: int = 0
    last_success: Optional[str] = None

    @classmethod
    def empty(cls, node) -> "NodeSnapshot":
        return cls(
            id=node.id,
            name=node.name,
            hostname=node.hostname,
            port=node.port,
            status="Error",
            error="Snapshot not available",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "port": self.port,
            "status": self.status,
            "version": self.version,
            "error": self.error,
            "fetched_at": self.fetched_at,
            "sessions": self.sessions,
            "session_count": self.session_count,
            "running_sessions": self.running_sessions,
            "last_success": self.last_success,
        }
