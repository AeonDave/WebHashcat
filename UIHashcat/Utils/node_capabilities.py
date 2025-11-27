from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Tuple


def _normalize_device_type(raw: Any) -> Optional[int]:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value in (1, 2, 3) else None


def _lower_list(values: Iterable[Any]) -> list[str]:
    return [str(item).lower() for item in values if isinstance(item, str)]


def _profile_from_system(device_type: Optional[int], system_info: Dict[str, Any]) -> Tuple[str, Optional[int]]:
    devices = _lower_list(system_info.get("devices", []))
    cpu_model = str(system_info.get("cpu_model") or "").lower()

    has_nvidia = any("nvidia" in d or "cuda" in d for d in devices)
    has_amd = any("amd" in d or "radeon" in d for d in devices)
    has_intel = any("intel" in d for d in devices)
    has_pocl = any("pocl" in d for d in devices)

    inferred_device_type = device_type
    if inferred_device_type is None:
        if has_nvidia or has_amd or has_intel:
            inferred_device_type = 2  # GPU hints found
        elif has_pocl or cpu_model:
            inferred_device_type = 1  # CPU hints found

    if inferred_device_type == 2:
        if has_nvidia:
            return "cuda", inferred_device_type
        if has_amd:
            return "amd-gpu", inferred_device_type
        if has_intel:
            return "intel-gpu", inferred_device_type
        return "gpu", inferred_device_type

    if inferred_device_type == 1:
        if has_pocl:
            return "pocl", inferred_device_type
        if has_intel or "intel" in cpu_model:
            return "intel-cpu", inferred_device_type
        if has_amd:
            return "cpu", inferred_device_type
        return "cpu", inferred_device_type

    if inferred_device_type == 3:
        return "accelerator", inferred_device_type

    return "unknown", inferred_device_type


def summarize_capabilities(info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return normalized device metadata for a node."""
    info = info or {}
    device_type = _normalize_device_type(info.get("device_type"))
    system_info = info.get("system") or {}

    profile, normalized_device_type = _profile_from_system(device_type, system_info)

    full_labels = {
        "cuda": "CUDA (GPU)",
        "amd-gpu": "AMD GPU",
        "intel-gpu": "Intel GPU",
        "intel-cpu": "Intel CPU",
        "pocl": "POCL (CPU)",
        "cpu": "CPU",
        "gpu": "GPU",
        "accelerator": "Co-processor",
        "unknown": "Unknown device",
    }

    return {
        "device_type": normalized_device_type,
        "profile": profile,
        "short_label": profile if profile != "unknown" else "unknown",
        "full_label": full_labels.get(profile, "Unknown device"),
    }


__all__ = ["summarize_capabilities"]
