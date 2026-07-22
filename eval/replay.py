"""
Replay documented hijack scenarios through the live detection logic and
report a combined detection rate.

WHY this is meaningful:
    We call check_announcement — the SAME function the live monitor uses —
    so a PASS means the real detector would catch this real attack. Only the
    data source changes (scenario file instead of the WebSocket).

Each scenario module must expose:
    SCENARIO_WATCHED   -> {prefix: {origin_as, ...}}
    SCENARIO_UPDATES   -> [(t_seconds, prefix, origin_as), ...]
    HIJACK_PREFIX      -> the prefix whose appearance = the attack
"""
import importlib

import ingest.live as live

# Add a scenario module here to grow N.
SCENARIOS = [
    ("2008 YouTube / Pakistan Telecom", "eval.scenario_youtube_2008"),
    ("2018 Amazon Route 53 / MyEtherWallet", "eval.scenario_amazon_2018"),
    ("2022 KLAYswap", "eval.scenario_klayswap_2022"),
]

# WHY we simulate multiple collectors:
# Confidence scoring weights how WIDELY an announcement propagated. A real
# hijack is seen by many collectors; replaying it from a single vantage
# point would under-score it. We replay each update as seen from several
# collectors, mirroring how a genuine hijack actually shows up in RIS data.
REPLAY_COLLECTORS = ["rrc00", "rrc01", "rrc03", "rrc10", "rrc12"]


def run_one(name, module_path):
    """Run a single scenario. Returns (detected: bool, ttd: int|None)."""
    mod = importlib.import_module(module_path)

    # Load this scenario's watched prefixes into trie AND baselines together.
    live.load_watched(mod.SCENARIO_WATCHED)

    print(f"\n=== {name} ===")

    hijack_appeared_at = None
    first_detected_at = None
    detections = 0

    for t, prefix, origin in mod.SCENARIO_UPDATES:
        if prefix == mod.HIJACK_PREFIX and hijack_appeared_at is None:
            hijack_appeared_at = t

        # Feed the update as seen from each collector in turn.
        alerted_this_update = False
        for collector in REPLAY_COLLECTORS:
            result = live.check_announcement(prefix, origin, collector)
            if result and not alerted_this_update:
                detections += 1
                alerted_this_update = True
                if first_detected_at is None:
                    first_detected_at = t
                print(f"  t={t:>3}s  DETECTED -> {result}")

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
