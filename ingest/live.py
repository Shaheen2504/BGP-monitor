"""
Connect to RIPE RIS Live and watch for BGP updates that hijack OUR prefixes.

Detection pipeline (as of this step):
    1. TRIE      -> is this prefix inside/equal to a watched prefix?
    2. BASELINE  -> what does 'normal' look like for that prefix?
    3. SCORER    -> how suspicious is this announcement (0-100)?
    4. ALERT     -> only if the score crosses the threshold.

WHY scoring instead of a binary check:
    A hard "unexpected origin = hijack" rule cries wolf constantly on live
    data. Scoring lets weak signals stay quiet and strong, corroborated ones
    (new origin + subprefix + wide collector spread) fire loudly.

Reliability:
    Live feeds drop constantly, so the main loop reconnects forever rather
    than crashing on the first hiccup.
"""
import asyncio
import json
import websockets

from config.watched_prefixes import WATCHED_PREFIXES
from detect.trie import PrefixTrie
from detect.baseline import PrefixBaseline, ConfidenceScorer
from detect.alerts import record_alert

RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/?client=bgp-monitor-learning"

SUBSCRIBE_MSG = {
    "type": "ris_subscribe",
    "data": {
        "type": "UPDATE",
        "moreSpecific": True,
        "socketOptions": {"includeRaw": False},
    },
}

# Build the trie once at startup — the watched set doesn't change at runtime.
TRIE = PrefixTrie()
for _prefix, _origins in WATCHED_PREFIXES.items():
    TRIE.insert(_prefix, _origins)

# One baseline per watched prefix. Seeded with the origins we already know
# are legitimate, so we don't alert on them from the very first update.
BASELINES = {}
for _prefix, _origins in WATCHED_PREFIXES.items():
    _b = PrefixBaseline()
    for _origin in _origins:
        _b.learn(origin=_origin, collector=None)
    BASELINES[_prefix] = _b

SCORER = ConfidenceScorer(alert_threshold=60)

# Tracks which collectors have reported each suspicious (prefix, origin) pair.
# WHY: a hijack's severity depends on how WIDELY it propagated. We can only
# know that by accumulating sightings across collectors over time.
SUSPICIOUS_SIGHTINGS = {}      # {(prefix, origin): set_of_collectors}



def load_watched(watched):
    """
    Load a watched-prefix set into BOTH the trie and the baselines.

    WHY this function exists:
        The trie ("which prefixes do I watch?") and the baselines ("what is
        normal for each?") must always describe the SAME prefix set. When
        those two were updated separately, swapping in a replay scenario
        updated one and not the other -> KeyError. Keeping the update in one
        place makes that class of bug impossible.

    Also resets sighting state, so one scenario's collector counts don't
    leak into the next.
    """
    global TRIE, BASELINES, SUSPICIOUS_SIGHTINGS

    TRIE = PrefixTrie()
    BASELINES = {}
    SUSPICIOUS_SIGHTINGS = {}

    for prefix, origins in watched.items():
        TRIE.insert(prefix, origins)
        b = PrefixBaseline()
        for origin in origins:
            b.learn(origin=origin, collector=None)
        BASELINES[prefix] = b


def check_announcement(prefix, origin, collector=None):
    """
    Classify one announcement using trie + baseline + confidence scoring.

    Returns a printable string, or None if this isn't worth reporting.
    """
    match = TRIE.search(prefix)
    if match is None:
        return None                       # not inside anything we watch

    watched_prefix, expected_origins = match
    baseline = BASELINES[watched_prefix]

    # Known-good origin -> normal traffic, learn from it and stay quiet.
    if origin in baseline.seen_origins:
        baseline.learn(origin=origin, collector=collector)
        return None

    # Something unexpected. Accumulate WHO has seen it, so repeated sightings
    # across different collectors raise the visibility signal over time.
    key = (prefix, origin)
    if key not in SUSPICIOUS_SIGHTINGS:
        SUSPICIOUS_SIGHTINGS[key] = set()
    if collector:
        SUSPICIOUS_SIGHTINGS[key].add(collector)
    collectors_seen = max(len(SUSPICIOUS_SIGHTINGS[key]), 1)

    is_subprefix = (prefix != watched_prefix)

    score, reasons = SCORER.score(
        origin=origin,
        collector=collector,
        baseline=baseline,
        is_subprefix=is_subprefix,
        total_collectors_seen=collectors_seen,
    )

    if not SCORER.should_alert(score):
        return None                       # below threshold — suppressed

    kind = "SUBPREFIX HIJACK" if is_subprefix else "ORIGIN HIJACK"

    # Store structured data for the dashboard/API, in addition to the
    # human-readable line we return for terminal output. Same event, two
    # consumers — keeping both in one place avoids them drifting apart.
    record_alert(prefix=prefix, origin=origin, watched_prefix=watched_prefix,
                 score=score, reasons=reasons, kind=kind, collector=collector)

    return (f"[score {score:>3}] {kind:<16} {prefix:<18} origin=AS{origin} "
            f"(inside {watched_prefix}) | " + ", ".join(reasons))


async def handle_messages(ws):
    """Read and classify messages off one live connection until it closes."""
    async for raw in ws:
        msg = json.loads(raw)
        if msg.get("type") != "ris_message":
            continue

        data = msg["data"]
        path = data.get("path", [])
        origin = path[-1] if path else None      # last hop = announcing AS
        collector = data.get("host")             # which RIS collector saw it

        for ann in data.get("announcements", []):
            for prefix in ann.get("prefixes", []):
                result = check_announcement(prefix, origin, collector)
                if result:
                    print(result)


async def stream_forever():
    """Connect, subscribe, read; reconnect forever on any failure."""
    while True:
        try:
            async with websockets.connect(RIS_LIVE_URL,
                                          ping_interval=None) as ws:
                await ws.send(json.dumps(SUBSCRIBE_MSG))
                print("Connected. Watching", len(WATCHED_PREFIXES),
                      "prefixes (trie + scoring active). Listening...\n")
                await handle_messages(ws)
        except Exception as e:
            print(f"[connection lost: {e}] reconnecting in 5s...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    try:
        asyncio.run(stream_forever())
    except KeyboardInterrupt:
        print("\nStopped.")
