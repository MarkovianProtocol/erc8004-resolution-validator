#!/usr/bin/env python3
"""Reference implementation of the Markovian integer work function (markovian.resolve.v2).

Pure stdlib. No numpy, no floats, no tolerance. Every quantity is a WAD fixed-point
(1e18-scaled) unsigned integer and the verdict is exact equality, so two honest
implementations can never disagree. This is the profile SPEC_V2.md pins; the float64
v1 function on the live chain is untouched.

    s_N = M^N . s   computed as N plain iterations of
    s'[i] = (M[i][0]*s[0])//WAD + (M[i][1]*s[1])//WAD + (M[i][2]*s[2])//WAD

Input derivation (from a 32-byte block hash): a,b,c = first three big-endian uint64;
s[i] = a_i*WAD // (a+b+c); the floor-division remainder (0..2 WAD-units) is added to
index 0 so the components sum to exactly WAD. a+b+c == 0 -> reject.

Forward-compatibility gate (checked BEFORE any arithmetic):
    - unknown version              -> reject
    - N > N_MAX (2^20)             -> reject
    - malformed M (entry > WAD or row sum != WAD) -> reject
    - s component > WAD, or s_in sum != WAD       -> reject

Reproduce this in any language and pass vectors/vectors_v2.json. Point to where it breaks.

Deps: none (stdlib only).
Exit 0 iff every vector matches its 'expect'; non-zero on any mismatch.
"""
import json
import os
import sys

WAD = 10**18
N_MAX = 1 << 20
SUPPORTED_VERSION = 2

# GENESIS_M v2: the exact WAD integers of the two-decimal float64 genesis values.
# 0.70 -> 700000000000000000 exactly -- no rounding anywhere. Rows each sum to WAD.
GENESIS_M_V2 = (
    (700000000000000000, 250000000000000000, 50000000000000000),   # from S0
    (100000000000000000, 750000000000000000, 150000000000000000),  # from S1
    (200000000000000000, 150000000000000000, 650000000000000000),  # from S2
)

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VECTORS = os.path.normpath(os.path.join(HERE, "..", "vectors", "vectors_v2.json"))


class Reject(ValueError):
    """Input is malformed under the v2 profile: classify as 'reject', never crash."""


def check_matrix(M):
    if len(M) != 3 or any(len(row) != 3 for row in M):
        raise Reject("M must be 3x3")
    for row in M:
        for m in row:
            if not (0 <= m <= WAD):
                raise Reject("matrix entry outside [0, WAD]")
        if sum(row) != WAD:
            raise Reject("matrix row sum != WAD")


def check_state(s, require_sum=False):
    if len(s) != 3:
        raise Reject("state must have 3 components")
    for x in s:
        if not (0 <= x <= WAD):
            raise Reject("state component outside [0, WAD]")
    if require_sum and sum(s) != WAD:
        raise Reject("state components must sum to exactly WAD")


def derive_s(block_hash):
    """Integerized input derivation: 3 big-endian uint64 from the first 24 hash bytes,
    floor-normalized to WAD; remainder (0..2) added to index 0 so the sum is exact."""
    raw = bytes.fromhex(block_hash[2:] if block_hash.startswith("0x") else block_hash)
    if len(raw) != 32:
        raise Reject("block hash must be 32 bytes")
    a = int.from_bytes(raw[0:8], "big")
    b = int.from_bytes(raw[8:16], "big")
    c = int.from_bytes(raw[16:24], "big")
    total = a + b + c
    if total == 0:
        raise Reject("derivation undefined: a+b+c == 0")
    s = [a * WAD // total, b * WAD // total, c * WAD // total]
    s[0] += WAD - (s[0] + s[1] + s[2])  # remainder rule: leftover WAD-units to index 0
    return s


def step(M, s):
    """One iteration: per-element floor((M[i][j]*s[j])/WAD), then sum the three terms."""
    return [
        (M[i][0] * s[0]) // WAD + (M[i][1] * s[1]) // WAD + (M[i][2] * s[2]) // WAD
        for i in range(3)
    ]


def work(M, s, N):
    """s_N = M^N . s by plain loop. No renormalization between iterations; the verdict
    downstream is exact equality of this final 3-vector. N == 0 is the identity."""
    if not (0 <= N <= N_MAX):
        raise Reject("N outside [0, N_MAX]")
    check_matrix(M)
    check_state(s, require_sum=True)
    out = list(s)
    for _ in range(N):
        out = step(M, out)
    return out


def evaluate(v):
    """Return the verifier's classification for one vector: True, False, or 'reject'.
    Gate order is normative: version, N, matrix, derivation, s_in, s_out_claimed, math."""
    try:
        if int(v.get("version", SUPPORTED_VERSION)) != SUPPORTED_VERSION:
            raise Reject("unknown version")
        N = int(v["N"])
        if not (0 <= N <= N_MAX):
            raise Reject("N outside [0, N_MAX]")
        M = [[int(x) for x in row] for row in v["M"]]
        check_matrix(M)
        if "hash" in v:
            s_in = derive_s(v["hash"])
            if "s_in" in v and [int(x) for x in v["s_in"]] != s_in:
                # The vector's listed s_in disagrees with the normative derivation:
                # that is a broken vector file, not a verdict. Surface it loudly.
                raise AssertionError("vector s_in != derive_s(hash): %s" % v.get("name"))
        else:
            s_in = [int(x) for x in v["s_in"]]
        check_state(s_in, require_sum=True)
        s_out_claimed = [int(x) for x in v["s_out"]]
        check_state(s_out_claimed, require_sum=False)
        return work(M, s_in, N) == s_out_claimed
    except Reject:
        return "reject"


def main(argv):
    path = argv[1] if len(argv) > 1 else DEFAULT_VECTORS
    doc = json.load(open(path))
    vectors = doc["vectors"]

    print("Markovian work-function conformance (%s)" % doc.get("profile", "markovian.resolve.v2"))
    print("vectors: %s\n" % os.path.abspath(path))

    all_ok = True
    for v in vectors:
        expect = v["expect"]
        got = evaluate(v)
        ok = (got == expect)
        all_ok = all_ok and ok
        print("  [%s] %-30s expect=%-6s got=%s" % ("PASS" if ok else "FAIL", v["name"], expect, got))

    print()
    if all_ok:
        print("RESULT: ALL %d VECTORS MATCH. Reimplement the work function and pass this file." % len(vectors))
        return 0
    print("RESULT: MISMATCH. A conformant implementation must reproduce every 'expect'.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
