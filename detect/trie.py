"""
A binary prefix trie for longest-prefix matching on IP prefixes.

WHY a trie (and not just a loop with ipaddress.subnet_of):
    This is the SAME data structure real routers and RPKI validators use to
    answer "which of my known prefixes contains this incoming address?" —
    called longest-prefix match. A loop works for 4 prefixes; a trie is what
    scales to a full routing table, and being able to say "I implemented
    longest-prefix match with a binary trie" is a real interview signal.

The core insight:
    An IP prefix is just the first N bits of an address. "Is prefix X inside
    prefix Y?" == "does X's bitstring START WITH Y's bitstring?". A trie —
    a tree where each step consumes one bit (0=left child, 1=right child) —
    turns that prefix-matching question into a simple walk down the tree.
"""
import ipaddress


def prefix_to_bits(prefix):
    """
    Convert a prefix like '8.8.0.0/16' into its network bitstring, e.g.
    '0000100000001000' (the first 16 bits of 8.8.0.0).

    WHY we only keep the first /N bits:
        The prefix length (/16) says how many bits are meaningful. The rest
        is wildcard and must be ignored — that's what makes 8.8.42.0/24 a
        child of 8.8.0.0/16 (they share those first 16 bits).

    We use Python's ipaddress library ONLY for parsing/validating the address
    here — the actual matching logic (the trie) we build ourselves. Parsing
    IPs correctly by hand (esp. IPv6) is error-prone and not the interesting
    part, so we lean on the stdlib for it.
    """
    net = ipaddress.ip_network(prefix, strict=False)
    # net.network_address as an integer, then as fixed-width binary.
    # IPv4 = 32 bits total, IPv6 = 128; we slice to the prefix length.
    total_bits = net.max_prefixlen                # 32 for v4, 128 for v6
    addr_int = int(net.network_address)
    full_bits = format(addr_int, f"0{total_bits}b")
    return full_bits[:net.prefixlen]              # keep only the meaningful bits


class TrieNode:
    """One node in the trie. Holds up to two children (bit 0 and bit 1)."""
    def __init__(self):
        self.children = {}       # {'0': TrieNode, '1': TrieNode}
        self.prefix = None       # set on nodes that ARE a watched prefix
        self.origins = None      # the legit origin AS(es) for that prefix


class PrefixTrie:
    """
    Stores watched prefixes and answers: for an incoming prefix, which
    watched prefix (if any) contains it?
    """
    def __init__(self):
        self.root = TrieNode()

    def insert(self, prefix, origins):
        """
        Add a watched prefix by walking its bits from the root, creating
        nodes as needed, and marking the final node as a real prefix.

        WHY mark the END node:
            Only the node where the bitstring ENDS represents that exact
            prefix. Intermediate nodes are just path — not prefixes we watch.
        """
        node = self.root
        for bit in prefix_to_bits(prefix):
            if bit not in node.children:
                node.children[bit] = TrieNode()
            node = node.children[bit]
        node.prefix = prefix       # this node now "is" 8.8.0.0/16
        node.origins = origins

    def search(self, prefix):
        """
        Walk the incoming prefix's bits down the trie. Every watched prefix
        we PASS THROUGH on the way is one that contains this prefix.

        Returns the MOST SPECIFIC (longest) containing watched prefix, or
        None if the incoming prefix isn't inside any watched prefix.

        WHY track the last match we passed through:
            Walking 8.8.42.0/24's bits, we pass the /16 node partway down.
            That pass-through IS the containment: /16 contains the /24. We
            keep the deepest such match because in routing, the most specific
            match is the one that actually governs traffic.
        """
        node = self.root
        last_match = None           # (prefix, origins) of deepest container

        for bit in prefix_to_bits(prefix):
            # Record any watched prefix we're sitting on as we descend.
            if node.prefix is not None:
                last_match = (node.prefix, node.origins)
            if bit not in node.children:
                break               # path diverges — no deeper match possible
            node = node.children[bit]

        # Check the final node too (handles exact-match, e.g. incoming == watched)
        if node.prefix is not None:
            last_match = (node.prefix, node.origins)

        return last_match
