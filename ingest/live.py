"""
Connect to RIPE RIS Live and watch for BGP updates that hijack OUR prefixes.

Big picture:
    RIS Live is a firehose of global BGP updates. We filter to a set of
    protected prefixes, then classify anything suspicious. As of Step 3 we
    detect TWO hijack shapes:
      - origin hijack:    someone announces our EXACT prefix with a wrong AS
      - subprefix hijack: someone announces a MORE-SPECIFIC slice of ours
                          (e.g. a /24 inside our /16) — steals traffic even
                          while our own announcement is still up. Toy tools
                          miss this; we catch it via a prefix trie.

Reliability note:
    Live feeds drop constantly, so the main loop reconnects forever rather
    than crashing on the first hiccup.
"""
import asyncio
import json
import websockets

from config.watched_prefixes import WATCHED_PREFIXES
from detect.trie import PrefixTrie

RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/?client=bgp-monitor-learning"

SUBSCRIBE_MSG = {
    "type": "ris_subscribe",
    "data": {
        "type": "UPDATE",
        "moreSpecific": True,
        "socketOptions": {"includeRaw": False},
    },
}

# Build the trie ONCE at startup from our watched list.
# WHY at module load: the watched set doesn't change while running, so we
# pay the build cost once instead of rebuilding per-announcement.
TRIE = PrefixTrie()
for _prefix, _origins in WATCHED_PREFIXES.items():
    TRIE.insert(_prefix, _origins)


def check_announcement(prefix, origin):
    """
    Classify one (prefix, origin) announcement against our watched prefixes.

    Steps:
      1. Ask the trie: is this prefix inside (or equal to) a watched prefix?
         - No  -> not ours, ignore (return None). This is the 99.9% case.
      2. If yes, we know the legit origin(s) for the containing prefix.
         - origin is legit           -> normal (OK)
         - origin is NOT legit, and
             incoming == watched      -> ORIGIN HIJACK (exact prefix, wrong AS)
             incoming more-specific   -> SUBPREFIX HIJACK (slice of ours)

    WHY distinguish the two hijack types:
        They're different attacks with different severity. A subprefix hijack
        is sneakier (your own route stays up, so naive monitoring sees
        nothing). Labelling them separately is exactly the nuance that shows
        you understand routing, not just string matching.
    """
    match = TRIE.search(prefix)
    if match is None:
        return None                       # not inside any watched prefix

    watched_prefix, expected_origins = match

    if origin in expected_origins:
        return f"OK          {prefix:<18} origin=AS{origin} (expected)"

    # Wrong origin for something inside our space -> a hijack. Which kind?
    if prefix == watched_prefix:
        kind = "ORIGIN HIJACK   "        # exact prefix announced by wrong AS
    else:
        kind = "SUBPREFIX HIJACK"        # more-specific slice of our prefix

    return (f"{kind} {prefix:<18} origin=AS{origin} "
            f"(inside {watched_prefix}, expected AS{expected_origins})")


async def handle_messages(ws):
    """Read and classify messages off one live connection until it closes."""
    async for raw in ws:
        msg = json.loads(raw)
        if msg.get("type") != "ris_message":
            continue

        data = msg["data"]
        path = data.get("path", [])
        origin = path[-1] if path else None    # last hop = announcing AS

        for ann in data.get("announcements", []):
            for prefix in ann.get("prefixes", []):
                result = check_announcement(prefix, origin)
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
                      "prefixes (trie loaded). Listening...\n")
                await handle_messages(ws)
        except Exception as e:
            print(f"[connection lost: {e}] reconnecting in 5s...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    try:
        asyncio.run(stream_forever())
    except KeyboardInterrupt:
        print("\nStopped.")
