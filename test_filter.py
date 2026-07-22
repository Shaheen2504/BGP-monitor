"""
Sanity test for scored detection. No live traffic.
"""
from ingest.live import check_announcement

# Known-good origin on a watched prefix -> quiet (None)
print("legit:    ", check_announcement("8.8.0.0/16", 15169, "rrc00"))

# Subprefix by unknown origin, one collector -> 40+30+6=76 -> ALERTS
print("subprefix:", check_announcement("8.8.42.0/24", 64500, "rrc01"))

# Unrelated prefix -> None
print("not ours: ", check_announcement("9.9.9.0/24", 12345, "rrc02"))
