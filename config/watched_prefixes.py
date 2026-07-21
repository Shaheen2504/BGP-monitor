"""
The prefixes we're protecting — the only ones the monitor reacts to.

WHY a defined list (not the whole Internet):
    A laptop can't meaningfully reason about ~1M constantly-changing prefixes.
    Real monitors (ARTEMIS included) watch a *defined set* owned by whoever
    runs the tool. We mirror that: a small set of well-known prefixes, so
    detection has a clear "is MY prefix being announced by the wrong AS?"
    question to answer.

WHY these specific prefixes:
    Famous, stable, and their true owners are publicly known — giving us
    ground truth to check origins against. Google/Cloudflare almost never
    change origin, so any deviation is genuinely suspicious.

FORMAT:
    prefix string -> set of AS number(s) that are the LEGITIMATE origin(s).
"""

WATCHED_PREFIXES = {
    "8.8.8.0/24": {15169},        # AS15169 = Google (public DNS)
    "1.1.1.0/24": {13335},        # AS13335 = Cloudflare (public DNS)
    "104.16.0.0/13": {13335},     # AS13335 = Cloudflare (main range)
    "8.8.0.0/16": {15169},        # AS15169 = Google (wider range)
}
