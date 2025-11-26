from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class SessionSnapshot:
    name: str
    node_id: int
    node_name: str
    response: str
    status: str
    crack_type: Optional[str]
    rule: Optional[str]
    mask: Optional[str]
    wordlist: Optional[str]
    time_estimated: Optional[str]
    time_started: Optional[str]
    progress: Optional[int]
    speed: Optional[str]
    reason: Optional[str]
    error: Optional[str]
    raw: Optional[Dict[str, Any]] = None
    fetched_at: Optional[str] = None

    @classmethod
    def from_error(cls, name, node_name, node_id, message: str):
        return cls(
            name=name,
            node_id=node_id,
            node_name=node_name,
            response="error",
            status="Error",
            crack_type=None,
            rule=None,
            mask=None,
            wordlist=None,
            time_estimated=None,
            time_started=None,
            progress=None,
            speed=None,
            reason=message,
            error=message,
            raw=None,
        )

    @classmethod
    def from_api_response(cls, session_name: str, node_name: str, node_id: int, session_info: Dict[str, Any],
                          fetched_at: Optional[str] = None):
        if not session_info:
            return cls.from_error(session_name, node_name, node_id, "No response from node")
        if session_info.get("response") == "error":
            message = session_info.get("message", "Node returned error")
            return cls.from_error(session_name, node_name, node_id, message)

        return cls(
            name=session_name,
            node_id=node_id,
            node_name=node_name,
            response="ok",
            status=session_info.get("status") or "Unknown",
            crack_type=session_info.get("crack_type"),
            rule=session_info.get("rule"),
            mask=session_info.get("mask"),
            wordlist=session_info.get("wordlist"),
            time_estimated=session_info.get("time_estimated"),
            time_started=session_info.get("time_started"),
            progress=session_info.get("progress"),
            speed=session_info.get("speed"),
            reason=session_info.get("reason"),
            error=None,
            raw=session_info,
            fetched_at=fetched_at,
        )

    def as_running_row(self, hashfile_name: str):
        crack_type = self.crack_type
        if crack_type == "dictionary":
            rule_mask = self.rule
            wordlist = self.wordlist
        elif crack_type == "mask":
            rule_mask = self.mask
            wordlist = ""
        else:
            rule_mask = ""
            wordlist = ""

        progress_display = f"{self.progress} %" if self.progress is not None else ""
        speed_value = self.speed.split("@")[0].strip() if self.speed else ""
        return {
            "hashfile": hashfile_name,
            "node": self.node_name,
            "type": crack_type,
            "rule_mask": rule_mask or "",
            "wordlist": wordlist or "",
            "remaining": self.time_estimated or "",
            "progress": progress_display,
            "speed": speed_value,
        }

    def as_error_row(self, hashfile_name: str, status_override: Optional[str] = None):
        status_value = status_override or self.status or "Error"
        return {
            "hashfile": hashfile_name,
            "node": self.node_name,
            "type": self.crack_type,
            "rule_mask": (self.rule if self.crack_type == "dictionary" else self.mask) or "",
            "wordlist": (self.wordlist if self.crack_type == "dictionary" else "") or "",
            "status": status_value,
            "reason": self.reason or self.error or "",
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "node_id": self.node_id,
            "node_name": self.node_name,
            "response": self.response,
            "status": self.status,
            "crack_type": self.crack_type,
            "rule": self.rule,
            "mask": self.mask,
            "wordlist": self.wordlist,
            "time_estimated": self.time_estimated,
            "time_started": self.time_started,
            "progress": self.progress,
            "speed": self.speed,
            "reason": self.reason,
            "error": self.error,
            "raw": self.raw,
            "fetched_at": self.fetched_at,
        }
