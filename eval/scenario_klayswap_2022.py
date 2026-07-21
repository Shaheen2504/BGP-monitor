"""
The 2022 KLAYswap BGP hijack, as a replay scenario.

WHAT REALLY HAPPENED (Feb 2022, documented):
    - A prefix serving a JavaScript SDK that KLAYswap (a Korean crypto
      service) loaded was legitimately originated by its true owner.
    - Attackers announced a MORE-SPECIFIC subprefix (via AS9457), pulling
      traffic for the SDK host to themselves and serving MALICIOUS
      JavaScript, which redirected users' crypto transfers.
    - Result: ~$1.9M stolen. Another subprefix hijack, this time weaponised
      to inject code rather than poison DNS.

NOTE on values: exact public prefixes vary by writeup; we use
representative values consistent with the documented event to exercise
the detector. The ATTACK TYPE (more-specific subprefix hijack) is faithful.

FORMAT: (t_seconds, prefix, origin_as), time-ordered.
"""

VICTIM_AS = 9848                          # legit origin of the SDK-host prefix
ATTACKER_AS = 9457                        # hijacking AS
VICTIM_PREFIX = "121.189.0.0/16"          # legit range serving the SDK
HIJACK_PREFIX = "121.189.44.0/24"         # more-specific slice inside it

SCENARIO_WATCHED = {
    VICTIM_PREFIX: {VICTIM_AS},
}

SCENARIO_UPDATES = [
    (0,  VICTIM_PREFIX, VICTIM_AS),        # normal
    (5,  VICTIM_PREFIX, VICTIM_AS),        # normal
    (50, HIJACK_PREFIX, ATTACKER_AS),      # THE HIJACK (subprefix)
    (55, HIJACK_PREFIX, ATTACKER_AS),      # persists
    (100, HIJACK_PREFIX, ATTACKER_AS),     # persists
]
