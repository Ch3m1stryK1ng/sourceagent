"""Token usage tracker with simple JSON persistence.

Stores daily token usage and last-reset date in `loot/token_usage.json`.
Provides synchronous helpers so callers from synchronous or async codepaths
can record usage without needing the event loop.
"""

import json
import threading
from datetime import date
from pathlib import Path
from typing import Any, Dict

# Persistent storage (loot root)
_data_file: Path = Path("loot/token_usage.json")
_data_lock = threading.Lock()

# In-memory cache
_data: Dict[str, Any] = {
    "daily_usage": 0,
    "last_reset_date": date.today().isoformat(),
    "last_input_tokens": 0,
    "last_output_tokens": 0,
    "last_total_tokens": 0,
}


def _load_unlocked() -> None:
    global _data
    if _data_file.exists():
        try:
            loaded = json.loads(_data_file.read_text(encoding="utf-8"))
            # Merge with defaults to be robust to schema changes
            d = {**_data, **(loaded or {})}
            _data = d
        except Exception:
            # Corrupt file -> reset to defaults
            _data = {
                "daily_usage": 0,
                "last_reset_date": date.today().isoformat(),
                "last_input_tokens": 0,
                "last_output_tokens": 0,
                "last_total_tokens": 0,
            }


def _save_unlocked() -> None:
    _data_file.parent.mkdir(parents=True, exist_ok=True)
    _data_file.write_text(json.dumps(_data, indent=2), encoding="utf-8")


def set_data_file(path: Path) -> None:
    """Override the data file (used by tests)."""
    global _data_file
    _data_file = path
    _load_unlocked()


def _daily_reset_if_needed_unlocked(current_iso: str) -> bool:
    """Reset daily usage if the date changed. Returns True if a reset occurred."""
    last = _data.get("last_reset_date")
    if last != current_iso:
        _data["daily_usage"] = 0
        _data["last_reset_date"] = current_iso
        return True
    return False


def record_usage_sync(input_tokens: int, output_tokens: int) -> None:
    """Record token usage synchronously.

    This updates last_* fields and increments daily_usage, performing a
    daily reset if the date changed.
    """
    try:
        input_tokens = int(input_tokens or 0)
        output_tokens = int(output_tokens or 0)
    except Exception:
        input_tokens = 0
        output_tokens = 0

    total = input_tokens + output_tokens
    today = date.today().isoformat()

    with _data_lock:
        # Load fresh copy
        _load_unlocked()
        _daily_reset_if_needed_unlocked(today)

        _data["last_input_tokens"] = input_tokens
        _data["last_output_tokens"] = output_tokens
        _data["last_total_tokens"] = total

        _data["daily_usage"] = int(_data.get("daily_usage", 0)) + total

        _save_unlocked()


def get_stats_sync() -> Dict[str, Any]:
    """Return a snapshot of current token usage stats.

    Keys:
      - daily_usage
      - last_reset_date
      - last_input_tokens
      - last_output_tokens
      - last_total_tokens
      - current_date
    """
    today = date.today().isoformat()
    with _data_lock:
        _load_unlocked()
        # Do NOT auto-reset on get_stats; callers should call record_usage or
        # explicitly invoke reset if needed. However, expose whether a reset
        # would occur now so callers (like the UI) can show it.
        would_reset = _data.get("last_reset_date") != today
        snap = dict(_data)
        snap["current_date"] = today
        snap["reset_pending"] = bool(would_reset)
        return snap


# Initialize at import time
try:
    _load_unlocked()
except Exception:
    pass
