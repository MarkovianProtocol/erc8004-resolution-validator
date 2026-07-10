#!/usr/bin/env python3
"""Markovian Pedersen+Schnorr prover — MUST match SchnorrPedersenVerifier.sol byte-for-byte.

Check enforced on-chain:  s_m*G + s_r*H == R + e*C   over BN128 G1.
  G = (1,2). H = nothing-up-my-sleeve generator from seed "MarkovianPedersenH/v1".
  context = keccak256(abi.encodePacked(requestHash b32, inputCommit b32, response u8, responseHash b32))
  e = uint256(keccak256(abi.encodePacked(Rx,Ry,Cx,Cy, context))) % n   (each Rx/Ry/Cx/Cy = 32 bytes)
  s_m = (k_m + e*m) % n ; s_r = (k_r + e*r) % n
  proof = abi.encode(uint256 Cx,Cy,Rx,Ry,s_m,s_r)
"""
import secrets
from eth_utils import keccak
from eth_abi import encode as abi_encode
from py_ecc.bn128 import G1, add, multiply, FQ, curve_order, field_modulus, is_on_curve, b as BN_B

N = curve_order            # 21888242871839275222246405745257275088548364400416034343698204186575808495617
P = field_modulus
SEED = "MarkovianPedersenH/v1"

assert (int(G1[0]), int(G1[1])) == (1, 2), "G1 must be (1,2)"
assert P % 4 == 3, "sqrt shortcut needs p % 4 == 3"


def derive_H(seed: str = SEED):
    """Deterministic hash-to-curve (try-and-increment) of a fixed seed.
    x = keccak(seed || ctr32) mod p; accept first ctr where x^3+3 is a QR; canonical y is even.
    BN128 G1 has cofactor 1, so any on-curve point is a valid group element."""
    seed_b = seed.encode()
    for ctr in range(0, 1024):
        x = int.from_bytes(keccak(seed_b + ctr.to_bytes(32, "big")), "big") % P
        rhs = (pow(x, 3, P) + 3) % P          # b = 3 for BN128
        if pow(rhs, (P - 1) // 2, P) != 1:    # not a quadratic residue
            continue
        y = pow(rhs, (P + 1) // 4, P)
        if y % 2 != 0:
            y = P - y                          # canonical: even y
        assert (y * y - rhs) % P == 0
        assert is_on_curve((FQ(x), FQ(y)), BN_B)
        return x, y, ctr
    raise RuntimeError("H derivation failed")


def _ints(Pt):
    return int(Pt[0]), int(Pt[1])


def context_hash(request_hash: bytes, input_commit: bytes, response: int, response_hash: bytes) -> bytes:
    assert len(request_hash) == 32 and len(input_commit) == 32 and len(response_hash) == 32
    assert 0 <= response <= 255
    return keccak(request_hash + input_commit + bytes([response]) + response_hash)  # abi.encodePacked


def challenge_e(Rx, Ry, Cx, Cy, context: bytes) -> int:
    packed = (Rx.to_bytes(32, "big") + Ry.to_bytes(32, "big")
              + Cx.to_bytes(32, "big") + Cy.to_bytes(32, "big") + context)
    return int.from_bytes(keccak(packed), "big") % N


def prove(request_hash: bytes, input_commit: bytes, response: int, response_hash: bytes,
          Hx: int, Hy: int, m=None, r=None, km=None, kr=None):
    """Produce a valid Pedersen+Schnorr proof bound to the exact verdict tuple."""
    m = secrets.randbelow(N) if m is None else m % N
    r = secrets.randbelow(N) if r is None else r % N
    km = secrets.randbelow(N) if km is None else km % N
    kr = secrets.randbelow(N) if kr is None else kr % N
    G = G1
    H = (FQ(Hx), FQ(Hy))
    C = add(multiply(G, m), multiply(H, r))
    R = add(multiply(G, km), multiply(H, kr))
    Cx, Cy = _ints(C)
    Rx, Ry = _ints(R)
    ctx = context_hash(request_hash, input_commit, response, response_hash)
    e = challenge_e(Rx, Ry, Cx, Cy, ctx)
    sm = (km + e * m) % N
    sr = (kr + e * r) % N
    proof = abi_encode(["uint256"] * 6, [Cx, Cy, Rx, Ry, sm, sr])
    return {"Cx": Cx, "Cy": Cy, "Rx": Rx, "Ry": Ry, "sm": sm, "sr": sr,
            "e": e, "context": "0x" + ctx.hex(), "proof": proof, "m": m, "r": r}


def verify_equation(Cx, Cy, Rx, Ry, sm, sr, request_hash: bytes, input_commit: bytes,
                    response: int, response_hash: bytes, Hx: int, Hy: int) -> bool:
    """Independent recompute of the exact on-chain check (used by verify.py)."""
    G = G1
    H = (FQ(Hx), FQ(Hy))
    C = (FQ(Cx), FQ(Cy))
    R = (FQ(Rx), FQ(Ry))
    ctx = context_hash(request_hash, input_commit, response, response_hash)
    e = challenge_e(Rx, Ry, Cx, Cy, ctx)
    lhs = add(multiply(G, sm % N), multiply(H, sr % N))
    rhs = add(R, multiply(C, e))
    return _ints(lhs) == _ints(rhs)


if __name__ == "__main__":
    Hx, Hy, ctr = derive_H()
    print("SEED   =", SEED)
    print("H ctr  =", ctr)
    print("Hx     =", Hx)
    print("Hy     =", Hy)
    # round-trip self-test
    import os
    rq, ic, rh = os.urandom(32), os.urandom(32), os.urandom(32)
    pr = prove(rq, ic, 100, rh, Hx, Hy)
    ok = verify_equation(pr["Cx"], pr["Cy"], pr["Rx"], pr["Ry"], pr["sm"], pr["sr"], rq, ic, 100, rh, Hx, Hy)
    print("self-test valid  proof verifies :", ok)
    bad = verify_equation(pr["Cx"], pr["Cy"], pr["Rx"], pr["Ry"], pr["sm"], pr["sr"], rq, ic, 0, rh, Hx, Hy)
    print("self-test flipped response fails :", not bad)
