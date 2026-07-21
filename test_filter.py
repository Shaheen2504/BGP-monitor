"""
Instant sanity test for check_announcement() with trie-based detection.
No live traffic needed — known inputs, known outputs, all cases covered.
"""
from ingest.live import check_announcement

# Legit: exact watched prefix, correct origin -> OK
print(check_announcement("8.8.0.0/16", 15169))

# Origin hijack: exact watched prefix, WRONG origin
print(check_announcement("8.8.0.0/16", 64500))

# Subprefix hijack: a /24 INSIDE our /16, wrong origin -> the sneaky one
print(check_announcement("8.8.42.0/24", 64500))

# Not ours: unrelated prefix -> None (ignored)
print(check_announcement("9.9.9.0/24", 12345))
