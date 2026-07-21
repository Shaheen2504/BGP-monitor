"""
Connect to RIPE RIS Live and watch for BGP updates touching OUR prefixes.

Big picture:
    RIS Live is a firehose of BGP updates from across the Internet. We filter
    it down to a small set of protected prefixes, so that when detection logic
    lands, we're only reasoning about traffic that concerns us.

Reliability note (important):
    A live network feed is NOT a stable thing. Connections drop, stall, and
    time out on any network blip. A monitor that crashes on the first hiccup
    is worthless — real monitoring must survive disconnects and come back on
    its own. So the main loop below RECONNECTS automatically and forever.
"""
import asyncio
import json
import websockets

# Our protected prefixes and their legitimate origin AS(es).
from config.watched_prefixes import WATCHED_PREFIXES

RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/?client=bgp-monitor-learning"

# WHY UPDATE only: it's the BGP message type that carries route
# announcements/withdrawals — the only type that can express a hijack.
SUBSCRIBE_MSG = {
    "type": "ris_subscribe",
    "data": {
        "type": "UPDATE",
        "moreSpecific": True,   # also catch more-specifics (needed later
                                # for subprefix-hijack detection)
        "socketOptions": {"includeRaw": False},
    },
}


def check_announcement(prefix, origin):
    """
    Decide what to report for one (prefix, origin) pair.

    WHY a separate function:
        The "is this interesting / suspicious?" decision lives in one place.
        When we add real hijack scoring in Step 3, we change only here — the
        networking code below never needs to know the rules.

    Current (naive first-cut) rule:
        - prefix not watched      -> ignore (return None)
        - watched, right origin   -> normal
        - watched, wrong origin   -> suspicious (right prefix, wrong announcer)
    """
    if prefix not in WATCHED_PREFIXES:
        return None

    expected_origins = WATCHED_PREFIXES[prefix]

    if origin in expected_origins:
        return f"OK        {prefix:<18} origin=AS{origin} (expected)"
    else:
        return (f"SUSPICIOUS {prefix:<18} origin=AS{origin} "
                f"(expected AS{expected_origins})")


async def handle_messages(ws):
    """
    Read messages off one live connection until it closes.

    Kept separate from the connection/retry logic so each function does one
    job: this one PARSES, the loop below CONNECTS-and-RECOVERS.
    """
    async for raw in ws:
        msg = json.loads(raw)

        # RIS wraps route data as "ris_message"; skip keepalives/status.
        if msg.get("type") != "ris_message":
            continue

        data = msg["data"]
        path = data.get("path", [])

        # The origin is the LAST hop of the AS-path: the network that
        # originally announced the prefix — i.e. the one claiming to own it.
        origin = path[-1] if path else None

        for ann in data.get("announcements", []):
            for prefix in ann.get("prefixes", []):
                result = check_announcement(prefix, origin)
                if result:
                    print(result)


async def stream_forever():
    """
    Connect, subscribe, and read — and if the connection dies for ANY
    reason, wait briefly and reconnect. This loop never gives up.

    WHY ping_interval=None:
        The default keepalive pings can false-trigger a "timeout" during
        quiet periods and kill the connection. RIS Live sends its own
        keepalives, so we turn the client-side ping off and instead rely on
        reconnecting if the stream truly goes silent.
    """
    while True:  # reconnect loop — the heart of the resilience
        try:
            async with websockets.connect(RIS_LIVE_URL,
                                          ping_interval=None) as ws:
                await ws.send(json.dumps(SUBSCRIBE_MSG))
                print("Connected. Watching", len(WATCHED_PREFIXES),
                      "prefixes. Listening for matches...\n")
                await handle_messages(ws)

        except Exception as e:
            # Any failure (timeout, drop, DNS glitch) lands here. We log it
            # and retry rather than crashing — that's the whole point.
            print(f"[connection lost: {e}] reconnecting in 5s...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    try:
        asyncio.run(stream_forever())
    except KeyboardInterrupt:
        print("\nStopped.")
