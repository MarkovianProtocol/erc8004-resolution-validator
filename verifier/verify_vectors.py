#!/usr/bin/env python3
"""Standalone conformance verifier for Markovian RESOLVE (markovian.resolve.v1).

Pure crypto. No chain RPC, no operator, no network. Reads vectors/vectors.json and,
for each vector, recomputes the Fiat-Shamir challenge and checks the Pedersen+Schnorr
binding equation on BN254 (alt_bn128) G1:

    s_m*G + s_r*H == R + e*C
    context = keccak256( requestHash[32] || inputCommit[32] || response[uint8] || responseHash[32] )
    e       = uint256( keccak256( Rx[32] || Ry[32] || Cx[32] || Cy[32] || context[32] ) ) mod n

Forward-compatibility gate (checked BEFORE any curve math):
    - unknown proof version  -> reject
    - response not in {0,100} -> reject

Reproduce this in any language and pass the same file. Point to where it breaks.

Deps: py_ecc, eth-utils   (pip install py_ecc eth-utils)
Exit 0 iff every vector matches its 'expect'; non-zero on any mismatch.
"""
import json
import os
import sys

from eth_utils import keccak
from py_ecc.bn128 import G1, add, multiply, FQ, curve_order, field_modulus, is_on_curve, b as BN_B

SUPPORTED_VERSION = 1
VALID_RESPONSES = (0, 100)

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VECTORS = os.path.normpath(os.path.join(HERE, "..", "vectors", "vectors.json"))


def b32(hexstr):
    raw = bytes.fromhex(hexstr[2:] if hexstr.startswith("0x") else hexstr)
    if len(raw) != 32:
        raise ValueError("expected 32 bytes, got %d" % len(raw))
    return raw


def context_hash(request_hash, input_commit, response, response_hash):
    if not (0 <= response <= 255):
        raise ValueError("response must fit a uint8")
    return keccak(request_hash + input_commit + bytes([response]) + response_hash)


def challenge_e(Rx, Ry, Cx, Cy, context, n):
    packed = (Rx.to_bytes(32, "big") + Ry.to_bytes(32, "big")
              + Cx.to_bytes(32, "big") + Cy.to_bytes(32, "big") + context)
    return int.from_bytes(keccak(packed), "big") % n


def equation_holds(v):
    """Recompute the exact on-chain check for one vector. Returns True/False."""
    n = int(v["n"])
    Hx, Hy = int(v["Hx"]), int(v["Hy"])
    Gx, Gy = int(v["G"][0]), int(v["G"][1])
    p = v["proof"]
    Cx, Cy = int(p["Cx"]), int(p["Cy"])
    Rx, Ry = int(p["Rx"]), int(p["Ry"])
    sm, sr = int(p["sm"]) % n, int(p["sr"]) % n

    G = (FQ(Gx), FQ(Gy))
    H = (FQ(Hx), FQ(Hy))
    C = (FQ(Cx), FQ(Cy))
    R = (FQ(Rx), FQ(Ry))

    ctx = context_hash(b32(v["requestHash"]), b32(v["inputCommit"]),
                       int(v["response"]), b32(v["responseHash"]))
    e = challenge_e(Rx, Ry, Cx, Cy, ctx, n)

    lhs = add(multiply(G, sm), multiply(H, sr))
    rhs = add(R, multiply(C, e))
    return (int(lhs[0]), int(lhs[1])) == (int(rhs[0]), int(rhs[1]))


def evaluate(v):
    """Return the verifier's classification: True, False, or 'reject'."""
    if int(v.get("version", SUPPORTED_VERSION)) != SUPPORTED_VERSION:
        return "reject"
    if int(v["response"]) not in VALID_RESPONSES:
        return "reject"
    return equation_holds(v)


def derive_H(seed):
    """Nothing-up-my-sleeve H, independently reproduced so H cannot be a backdoor."""
    seed_b = seed.encode()
    for ctr in range(0, 1024):
        x = int.from_bytes(keccak(seed_b + ctr.to_bytes(32, "big")), "big") % field_modulus
        rhs = (pow(x, 3, field_modulus) + 3) % field_modulus
        if pow(rhs, (field_modulus - 1) // 2, field_modulus) != 1:
            continue
        y = pow(rhs, (field_modulus + 1) // 4, field_modulus)
        if y % 2 != 0:
            y = field_modulus - y
        assert is_on_curve((FQ(x), FQ(y)), BN_B)
        return x, y, ctr
    raise RuntimeError("H derivation failed")


def main(argv):
    path = argv[1] if len(argv) > 1 else DEFAULT_VECTORS
    doc = json.load(open(path))
    vectors = doc["vectors"]

    print("Markovian RESOLVE conformance (%s)" % doc.get("profile", "markovian.resolve.v1"))
    print("vectors: %s\n" % os.path.abspath(path))

    # Independent H reproduction (nothing-up-my-sleeve check).
    h = doc.get("curve", {}).get("H", {})
    h_ok = True
    if "seed" in h:
        Hx, Hy, ctr = derive_H(h["seed"])
        h_ok = (Hx == int(h["Hx"]) and Hy == int(h["Hy"]))
        print("  [%s] H reproduced from seed '%s' (ctr=%d) matches curve.H"
              % ("PASS" if h_ok else "FAIL", h["seed"], ctr))
        print()

    all_ok = h_ok
    for v in vectors:
        expect = v["expect"]
        got = evaluate(v)
        ok = (got == expect)
        all_ok = all_ok and ok
        print("  [%s] %-26s expect=%-6s got=%s" % ("PASS" if ok else "FAIL", v["name"], expect, got))

    print()
    if all_ok:
        print("RESULT: ALL %d VECTORS MATCH. Reimplement the verifier and pass this file." % len(vectors))
        return 0
    print("RESULT: MISMATCH. A conformant verifier must reproduce every 'expect'.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
