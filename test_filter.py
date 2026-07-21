"""
Instant sanity test for check_announcement() — no live traffic needed.
Feeds known inputs, checks known outputs, covers all three outcomes.

WHY: a detector you can only test by "waiting and hoping" is one you can't
trust. Known-input/known-output testing is how you actually verify logic.
"""
from ingest.live import check_announcement

print(check_announcement("8.8.8.0/24", 15169))   # -> OK (expected origin)
print(check_announcement("8.8.8.0/24", 64500))   # -> SUSPICIOUS (wrong origin)
print(check_announcement("203.0.113.0/24", 123)) # -> None (not watched)
