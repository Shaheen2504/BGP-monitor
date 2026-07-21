"""
Replay ALL documented hijack scenarios through the live detection logic and
report a combined detection rate.

WHY this matters for the resume:
    Each scenario reconstructs a REAL, documented hijack (real ASNs and
    prefixes) and runs it through check_announcement — the SAME function the
    live monitor uses. A combined "detected N/N" is the validated number
    that backs the resume line.

Each scenario module must expose:
    SCENARIO_WATCHED   -> {prefix: {origin_as, ...}}
    SCENARIO_UPDATES   -> [(t_seconds, prefix, origin_as), ...]
    HIJACK_PREFIX      -> the prefix whose appearance = the attack
"""
import importlib

import ingest.live as live
from detect.trie import PrefixTrie

# The scenarios to validate against. Add a new module here to grow N.
SCENARIOS = [
    ("2008 YouTube / Pakistan Telecom", "eval.scenario_youtube_2008"),
    ("2018 Amazon Route 53 / MyEtherWallet", "eval.scenario_amazon_2018"),
    ("2022 KLAYswap", "eval.scenario_klayswap_2022"),
]


def run_one(name, module_path):
    """
    Run a single scenario. Returns (detected: bool, ttd: int|None).

    WHY we rebuild the trie per scenario:
        Each documented event protects a different prefix. We load THIS
        scenario's watched set into the detector's trie so check_announcement
        reasons about the right prefix, then feed the scenario's updates.
    """
    mod = importlib.import_module(module_path)

    # Point the shared detector at this scenario's watched prefixes.
    live.TRIE = PrefixTrie()
    for prefix, origins in mod.SCENARIO_WATCHED.items():
        live.TRIE.insert(prefix, origins)

    print(f"\n=== {name} ===")

    hijack_appeared_at = None
    first_detected_at = None
    detections = 0

    for t, prefix, origin in mod.SCENARIO_UPDATES:
        result = live.check_announcement(prefix, origin)

        if prefix == mod.HIJACK_PREFIX and hijack_appeared_at is None:
            hijack_appeared_at = t

        if result and "HIJACK" in result:
            detections += 1
            if first_detected_at is None:
                first_detected_at = t
            print(f"  t={t:>3}s  DETECTED -> {result}")
        elif result:
            print(f"  t={t:>3}s  {result}")

    detected = detections > 0
    ttd = None
    if hijack_appeared_at is not None and first_detected_at is not None:
        ttd = first_detected_at - hijack_appeared_at

    print(f"  -> {'PASS' if detected else 'FAIL'} "
          f"({detections} hijack update(s) flagged)")
    return detected, ttd


def run():
    passed = 0
    for name, path in SCENARIOS:
        detected, _ = run_one(name, path)
        if detected:
            passed += 1

    total = len(SCENARIOS)
    print("\n" + "=" * 40)
    print(f"HISTORICAL HIJACK VALIDATION: detected {passed}/{total}")
    print("=" * 40)


if __name__ == "__main__":
    run()
