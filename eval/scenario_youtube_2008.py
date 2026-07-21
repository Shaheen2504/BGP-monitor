"""
The 2008 YouTube / Pakistan Telecom hijack, as a replay scenario.

WHAT REALLY HAPPENED (24 Feb 2008, documented by RIPE):
    - YouTube (AS36561) legitimately originated 208.65.152.0/22.
    - Pakistan Telecom (AS17557), told to block YouTube locally, announced
      a MORE-SPECIFIC 208.65.153.0/24. Because routers prefer the most
      specific prefix, YouTube traffic worldwide was pulled to Pakistan.
    - Result: YouTube globally unreachable for ~2 hours. A textbook
      subprefix hijack — exactly what our trie is built to catch.

WHY a scenario file (be honest in interviews):
    Historical BGP archives require a fragile C toolchain to read. Instead
    we encode the DOCUMENTED event (real ASNs, real prefixes) as a sequence
    of updates and feed them through the SAME detection code the live
    monitor uses. We validate the detector, not the data plumbing.

FORMAT: each update is (t_seconds, prefix, origin_as) in time order.
    t_seconds is offset from scenario start, so we can measure how quickly
    detection fires relative to when the hijack appears.
"""

# Real values from the documented event.
YOUTUBE_AS = 36561
PAKISTAN_TELECOM_AS = 17557
YOUTUBE_PREFIX = "208.65.152.0/22"
HIJACK_PREFIX = "208.65.153.0/24"   # more-specific slice inside the /22

# The watched-prefix config this scenario assumes (YouTube's legit prefix).
SCENARIO_WATCHED = {
    YOUTUBE_PREFIX: {YOUTUBE_AS},
}

# The timeline of updates we replay.
SCENARIO_UPDATES = [
    # Normal operation: YouTube announces its own prefix, correctly.
    (0,  YOUTUBE_PREFIX, YOUTUBE_AS),
    (5,  YOUTUBE_PREFIX, YOUTUBE_AS),

    # THE HIJACK: Pakistan Telecom announces a more-specific subprefix.
    # This is the moment detection must fire.
    (30, HIJACK_PREFIX, PAKISTAN_TELECOM_AS),

    # Hijack persists (real event lasted ~2 hours; we compress it).
    (35, HIJACK_PREFIX, PAKISTAN_TELECOM_AS),
    (60, HIJACK_PREFIX, PAKISTAN_TELECOM_AS),
]
