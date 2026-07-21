"""
Replay a documented hijack scenario through the live detection logic and
report whether/when it was detected.

WHY this is meaningful:
    We import check_announcement — the SAME function the live monitor runs.
    We only swap the data source (scenario file instead of the WebSocket).
    So a PASS here means the real detector would catch this real attack.

WHAT WE MEASURE:
    - detection rate: did we flag the hijack update(s)?
    - time-to-detect: scenario-time between hijack appearing and first alert.
      (Here it's effectively instant since we process in order, but the
       harness is built to measure it — important once detection gets more
       stateful in later steps.)
"""
import ingest.live as live
from eval.scenario_youtube_2008 import (
    SCENARIO_WATCHED, SCENARIO_UPDATES, HIJACK_PREFIX,
)


def run():
    # Point the detector's trie at THIS scenario's watched prefixes.
    # WHY rebuild the trie: the live module built its trie from the real
    # config; for the replay we want the scenario's watched set instead.
    from detect.trie import PrefixTrie
    live.TRIE = PrefixTrie()
    for prefix, origins in SCENARIO_WATCHED.items():
        live.TRIE.insert(prefix, origins)

    print("Replaying 2008 YouTube/Pakistan Telecom hijack scenario\n")

    hijack_appeared_at = None
    first_detected_at = None
    detections = 0

    for t, prefix, origin in SCENARIO_UPDATES:
        result = live.check_announcement(prefix, origin)

        # Note when the hijack update first appears in the timeline.
        if prefix == HIJACK_PREFIX and hijack_appeared_at is None:
            hijack_appeared_at = t

        # A non-OK, non-None result on the hijack prefix = a detection.
        if result and "HIJACK" in result:
            detections += 1
            if first_detected_at is None:
                first_detected_at = t
            print(f"  t={t:>3}s  DETECTED -> {result}")
        elif result:
            print(f"  t={t:>3}s  {result}")

    # Summary — these are the numbers that go on your resume.
    print("\n--- Results ---")
    print(f"Hijack appeared at:   t={hijack_appeared_at}s")
    print(f"First detected at:    t={first_detected_at}s")
    if hijack_appeared_at is not None and first_detected_at is not None:
        ttd = first_detected_at - hijack_appeared_at
        print(f"Time to detect:       {ttd}s")
    print(f"Total hijack updates flagged: {detections}")
    print(f"Detection: {'PASS' if detections > 0 else 'FAIL'}")


if __name__ == "__main__":
    run()
