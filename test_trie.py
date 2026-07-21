"""
Prove the trie does longest-prefix match correctly, with no live data.
Covers: exact match, subprefix (inside), and unrelated (outside).
"""
from detect.trie import PrefixTrie

trie = PrefixTrie()
trie.insert("8.8.0.0/16", {15169})    # Google's /16
trie.insert("1.1.1.0/24", {13335})    # Cloudflare's /24

# 1) EXACT match: incoming == watched -> should find 8.8.0.0/16
print("exact   ", trie.search("8.8.0.0/16"))

# 2) SUBPREFIX: 8.8.42.0/24 is INSIDE 8.8.0.0/16 -> should find the /16
#    THIS is the hijack case exact-match tools miss.
print("subprefix", trie.search("8.8.42.0/24"))

# 3) UNRELATED: 9.9.9.0/24 is not inside anything watched -> None
print("outside ", trie.search("9.9.9.0/24"))
