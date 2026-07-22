"""
Per-prefix baselines and confidence scoring.

WHY this exists (the false-positive problem):
    The Step 3 detector treats ANY unexpected origin as a hijack. On live
    data that's far too trigger-happy: a prefix can legitimately shift
    origins, gain upstreams, or appear via new collectors during normal
    operation. Alerting on every deviation buries real hijacks in noise.

    So instead of a binary decision, we:
      1. LEARN each prefix's normal behaviour (origins, collectors) during a
         warm-up window  -> the "baseline".
      2. SCORE how surprising a new announcement is against that baseline,
         combining several signals into a 0-100 confidence.
      3. Only ALERT when the score crosses a threshold.

    "How do you handle false positives?" is THE question interviewers ask
    about any detector. This is the answer.
"""


class PrefixBaseline:
    """
    Remembers what 'normal' looks like for ONE watched prefix.

    We track which origin ASes have announced it and which collectors
    reported it. During warm-up we only observe; afterwards we judge new
    announcements against what we learned.
    """
    def __init__(self):
        self.seen_origins = set()       # origin ASes observed as normal
        self.seen_collectors = set()    # collectors that have reported it

    def learn(self, origin, collector):
        """Record one observed announcement as part of 'normal'."""
        if origin is not None:
            self.seen_origins.add(origin)
        if collector is not None:
            self.seen_collectors.add(collector)


class ConfidenceScorer:
    """
    Turns one announcement + its baseline into a 0-100 suspicion score.

    WHY a weighted sum (not ML, yet):
        A transparent, explainable scoring function is the right first tool.
        You can defend every point in an interview ("a new origin adds 40
        because that's the strongest hijack signal"). ML comes later as a
        SEPARATE layer; you don't lead with a black box.
    """

    # WHY these weights: a never-before-seen origin is the strongest single
    # hijack signal, so it dominates. A subprefix is inherently suspicious
    # (the sneaky attack). Wide collector visibility means the bad route
    # actually propagated -> more likely real than a local blip.
    NEW_ORIGIN_POINTS = 40
    SUBPREFIX_POINTS = 30
    MAX_VISIBILITY_POINTS = 30

    def __init__(self, alert_threshold=60):
        # WHY 60: high enough that one mild signal won't fire, low enough
        # that a new-origin subprefix (40+30) always does. Tunable.
        self.alert_threshold = alert_threshold

    def score(self, origin, collector, baseline, is_subprefix,
              total_collectors_seen):
        """
        Compute a suspicion score plus the reasons behind it.

        total_collectors_seen = how many DISTINCT collectors have reported
        this suspicious announcement (wide spread = more likely real).

        Returning the REASONS is deliberate: an alert you can explain
        ("new origin + subprefix + wide spread") is worth far more than a
        bare number.
        """
        score = 0
        reasons = []

        # Signal 1: an origin we've never seen for this prefix.
        if origin not in baseline.seen_origins:
            score += self.NEW_ORIGIN_POINTS
            reasons.append(f"new origin AS{origin} (+{self.NEW_ORIGIN_POINTS})")

        # Signal 2: it's a more-specific slice of our prefix.
        if is_subprefix:
            score += self.SUBPREFIX_POINTS
            reasons.append(f"subprefix announcement (+{self.SUBPREFIX_POINTS})")

        # Signal 3: collector visibility, scaled 0..MAX.
        # We treat ~5+ distinct collectors as full visibility.
        visibility_fraction = min(total_collectors_seen / 5.0, 1.0)
        visibility_points = round(self.MAX_VISIBILITY_POINTS * visibility_fraction)
        if visibility_points > 0:
            score += visibility_points
            reasons.append(f"seen by {total_collectors_seen} collector(s) "
                           f"(+{visibility_points})")

        return min(score, 100), reasons

    def should_alert(self, score):
        return score >= self.alert_threshold
