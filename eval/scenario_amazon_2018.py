"""
The 2018 Amazon Route 53 / MyEtherWallet BGP hijack, as a replay scenario.

WHAT REALLY HAPPENED (24 Apr 2018, widely documented):
    - Amazon (AS16509) legitimately originated Route 53 DNS ranges,
      including 205.251.192.0/23.
    - Attacker AS10297 (eNet) announced MORE-SPECIFIC /24 subprefixes of
      that range. Routers preferred the more-specifics, pulling Amazon DNS
      traffic to the attacker, who returned forged DNS answers redirecting
      MyEtherWallet users to a phishing server.
    - Result: ~$150K in Ethereum stolen. A subprefix hijack used to
      poison DNS — precisely the more-specific attack our trie catches.

FORMAT: (t_seconds, prefix, origin_as), time-ordered.
"""

AMAZON_AS = 16509
ATTACKER_AS = 10297
AMAZON_PREFIX = "205.251.192.0/23"        # legit Amazon Route 53 range
HIJACK_PREFIX = "205.251.193.0/24"        # more-specific slice inside it

SCENARIO_WATCHED = {
    AMAZON_PREFIX: {AMAZON_AS},
}

SCENARIO_UPDATES = [
    (0,  AMAZON_PREFIX, AMAZON_AS),        # normal
    (5,  AMAZON_PREFIX, AMAZON_AS),        # normal
    (40, HIJACK_PREFIX, ATTACKER_AS),      # THE HIJACK (subprefix)
    (45, HIJACK_PREFIX, ATTACKER_AS),      # persists
    (90, HIJACK_PREFIX, ATTACKER_AS),      # persists
]
