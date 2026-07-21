"""
Connect to RIPE RIS Live and print BGP UPDATE announcements.
Docs: https://ris-live.ripe.net/manual/
"""
import asyncio
import json
import websockets

RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/?client=bgp-monitor-learning"

SUBSCRIBE_MSG = {
    "type": "ris_subscribe",
    "data": {
        "type": "UPDATE",
        "moreSpecific": True,
        "socketOptions": {"includeRaw": False},
    },
}


async def stream():
    async with websockets.connect(RIS_LIVE_URL, ping_interval=20) as ws:
        await ws.send(json.dumps(SUBSCRIBE_MSG))
        print("Connected to RIS Live. Waiting for updates...\n")

        async for raw in ws:
            msg = json.loads(raw)
            if msg.get("type") != "ris_message":
                continue

            data = msg["data"]
            collector = data.get("host")
            path = data.get("path", [])
            origin = path[-1] if path else None

            for ann in data.get("announcements", []):
                for prefix in ann.get("prefixes", []):
                    print(
                        f"[{collector}] {prefix:<20} "
                        f"origin=AS{origin} "
                        f"path_len={len(path)}"
                    )


if __name__ == "__main__":
    try:
        asyncio.run(stream())
    except KeyboardInterrupt:
        print("\nStopped.")
