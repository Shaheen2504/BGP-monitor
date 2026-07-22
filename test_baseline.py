"""
Prove baseline + scoring behaves sensibly. No live data needed.
"""
from detect.baseline import PrefixBaseline, ConfidenceScorer

# Baseline: we've normally seen this prefix announced by AS15169.
base = PrefixBaseline()
base.learn(origin=15169, collector="rrc00")
base.learn(origin=15169, collector="rrc01")

scorer = ConfidenceScorer(alert_threshold=60)

# A: normal — known origin, exact prefix, 1 collector -> should NOT alert
score_a, reasons_a = scorer.score(
    origin=15169, collector="rrc00", baseline=base,
    is_subprefix=False, total_collectors_seen=1)
print("A normal:    ", score_a, scorer.should_alert(score_a), reasons_a)

# B: subprefix hijack by NEW origin, seen widely -> should ALERT
score_b, reasons_b = scorer.score(
    origin=64500, collector="rrc12", baseline=base,
    is_subprefix=True, total_collectors_seen=5)
print("B hijack:    ", score_b, scorer.should_alert(score_b), reasons_b)

# C: new origin but only ONE collector saw it -> probably noise, NO alert
score_c, reasons_c = scorer.score(
    origin=64500, collector="rrc12", baseline=base,
    is_subprefix=False, total_collectors_seen=1)
print("C borderline:", score_c, scorer.should_alert(score_c), reasons_c)
