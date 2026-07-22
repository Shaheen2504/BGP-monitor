"""
Shared alert store — the bridge between the monitor and the web API.

WHY deduplicate by (prefix, origin):
    A single hijack is seen by MANY collectors, and each sighting hits
    check_announcement separately. Naively appending one row per sighting
    turns one incident into a wall of near-identical alerts — the alert
    fatigue problem real SOC teams complain about. Instead we treat
    (prefix, origin) as ONE INCIDENT: first_seen stays fixed, while score,
    collector count, and last_seen update as evidence accumulates.

    This is also why the score rising over time is visible rather than lost:
    the incident's score reflects the strongest evidence so far.

WHY capped length:
    A long-running monitor would grow this unbounded. We keep the most
    recent N incidents, which is what a dashboard actually displays.
"""
from collections import OrderedDict
from datetime import datetime, timezone

MAX_ALERTS = 200

# key: (prefix, origin) -> incident dict. OrderedDict lets us evict oldest.
_INCIDENTS = OrderedDict()


def record_alert(prefix, origin, watched_prefix, score, reasons,
                 kind, collector=None):
    """
    Record or UPDATE one incident.

    New incident  -> create with first_seen.
    Seen before   -> keep first_seen, bump last_seen, track the collector,
                     and raise the score only if this sighting is stronger.
    """
    key = (prefix, origin)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if key in _INCIDENTS:
        inc = _INCIDENTS[key]
        inc["last_seen"] = now
        if collector:
            inc["collectors"].add(collector)
        # Keep the highest score seen — evidence only strengthens a case.
        if score > inc["score"]:
            inc["score"] = score
            inc["reasons"] = reasons
        _INCIDENTS.move_to_end(key)      # most recently active goes last
    else:
        _INCIDENTS[key] = {
            "first_seen": now,
            "last_seen": now,
            "kind": kind,
            "prefix": prefix,
            "origin": origin,
            "watched_prefix": watched_prefix,
            "score": score,
            "reasons": reasons,
            "collectors": {collector} if collector else set(),
        }
        if len(_INCIDENTS) > MAX_ALERTS:
            _INCIDENTS.popitem(last=False)   # evict oldest


def get_alerts():
    """
    Return incidents newest-active-first, JSON-serializable.

    Sets aren't JSON-serializable, so collectors becomes a count + list.
    """
    out = []
    for inc in reversed(_INCIDENTS.values()):
        item = dict(inc)
        cols = item.pop("collectors")
        item["collector_count"] = len(cols)
        item["collectors"] = sorted(c for c in cols if c)
        out.append(item)
    return out
