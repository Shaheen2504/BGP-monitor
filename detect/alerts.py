"""
Shared alert store — the bridge between the monitor and the web API.

WHY a module-level list:
    The monitor (async background task) and the FastAPI request handlers run
    in the SAME process, so they can share memory directly. The monitor
    appends; the API reads. No database, no IPC, no serialization — the
    simplest thing that works for v1.

WHY capped length:
    A monitor left running for days would grow this list forever and
    eventually exhaust memory. Keeping only the most recent N alerts bounds
    memory and matches what a dashboard actually shows.
"""
from collections import deque
from datetime import datetime, timezone

MAX_ALERTS = 200

# deque with maxlen automatically discards the oldest when full.
ALERTS = deque(maxlen=MAX_ALERTS)


def record_alert(prefix, origin, watched_prefix, score, reasons,
                 kind, collector=None):
    """Store one alert as structured data the API can serve as JSON."""
    ALERTS.appendleft({
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kind": kind,                  # ORIGIN HIJACK / SUBPREFIX HIJACK
        "prefix": prefix,              # what was announced
        "origin": origin,              # who announced it
        "watched_prefix": watched_prefix,  # ours that it falls inside
        "score": score,                # 0-100 confidence
        "reasons": reasons,            # why we scored it that way
        "collector": collector,
    })


def get_alerts():
    """Return alerts newest-first as a plain list (JSON-serializable)."""
    return list(ALERTS)
