#!/usr/bin/env python3
"""
Self-contained tests for the v2 integer work function. Run:  python3 test_workfn_v2.py
Exit 0 = all green. No test framework dependency, no numpy in the normative path.

The float64 cross-check at the bottom is INFORMATIVE only: it shows the WAD
integerization is faithful to the live chain's float64 v1 (within ~1e-9), it is
NOT a conformance requirement — conformance is exact equality on vectors_v2.json.
"""
import sys

from workfn_v2 import (
    WAD, N_MAX, GENESIS_M_V2, Reject,
    check_matrix, check_state, derive_s, step, work, evaluate,
)

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  OK   " + name)
    else:
        FAIL += 1
        print("  FAIL " + name)


def rejects(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
        return False
    except Reject:
        return True


UNIFORM = [WAD // 3 + (WAD - 3 * (WAD // 3)), WAD // 3, WAD // 3]  # remainder to index 0

# --- constants are exact ---
check("WAD == 10^18", WAD == 10**18)
check("N_MAX == 2^20", N_MAX == 1 << 20)
check("GENESIS_M_V2[0][0] is the exact WAD of 0.70",
      GENESIS_M_V2[0][0] == 700000000000000000)
check("every GENESIS_M_V2 row sums to exactly WAD",
      all(sum(row) == WAD for row in GENESIS_M_V2))

# --- derivation: floor + remainder-to-index-0 ---
h_ones = "0x" + "01" * 24 + "00" * 8  # a == b == c -> WAD/3 each, remainder 1
s = derive_s(h_ones)
check("equal uint64s derive the uniform vector, remainder 1 to index 0", s == UNIFORM)
check("derived vector sums to exactly WAD", sum(s) == WAD)
h_ab = "0x" + "00" * 7 + "01" + "00" * 7 + "02" + "00" * 16  # a=1, b=2, c=0
s = derive_s(h_ab)
check("a=1,b=2,c=0 floors to [1/3, 2/3, 0] with remainder 1 to index 0",
      s == [WAD // 3 + 1, 2 * WAD // 3, 0] and sum(s) == WAD)
check("naive nearest-rounding would differ (2/3 rounds up): floor is normative",
      round(2 * WAD / 3) != 2 * WAD // 3)
check("zero-total derivation rejects (v1 divides by zero here)",
      rejects(derive_s, "0x" + "00" * 32))
check("31-byte hash rejects", rejects(derive_s, "0x" + "11" * 31))

# --- iteration semantics ---
check("N=0 is the identity", work(GENESIS_M_V2, UNIFORM, 0) == UNIFORM)
s1 = step(GENESIS_M_V2, UNIFORM)
check("N=1 by work() == one step()", work(GENESIS_M_V2, UNIFORM, 1) == s1)
check("per-element floor then sum (not floor of the row sum)",
      step(GENESIS_M_V2, [1, 1, WAD - 2]) ==
      [(GENESIS_M_V2[i][0] * 1) // WAD + (GENESIS_M_V2[i][1] * 1) // WAD
       + (GENESIS_M_V2[i][2] * (WAD - 2)) // WAD for i in range(3)])
check("M is row-stochastic acting on a column vector: sum is NOT preserved "
      "(s=[0,WAD,0] -> column-1 sum 1.15 WAD, minus floor loss)",
      sum(step(GENESIS_M_V2, [0, WAD, 0])) == 1150000000000000000)
check("max component never grows (rows sum to WAD): stays <= WAD for all N",
      all(x <= WAD for x in work(GENESIS_M_V2, [0, WAD, 0], 50)))
check("N == N_MAX is accepted (boundary): 2^20 iterations run exactly",
      len(work(GENESIS_M_V2, UNIFORM, N_MAX)) == 3)
check("N == N_MAX + 1 rejects", rejects(work, GENESIS_M_V2, UNIFORM, N_MAX + 1))

# --- malformed input gates ---
check("matrix row sum != WAD rejects",
      rejects(check_matrix, [[WAD, 0, 0], [0, WAD, 0], [0, 0, WAD - 1]]))
check("matrix entry > WAD rejects",
      rejects(check_matrix, [[WAD + 1, 0, 0], [0, WAD, 0], [0, 0, WAD]]))
check("state component > WAD rejects", rejects(check_state, [WAD + 1, 0, 0]))
check("s_in sum != WAD rejects", rejects(check_state, [1, 2, 3], require_sum=True))
check("negative component rejects", rejects(check_state, [-1, 1, WAD]))

# --- evaluate() classification ---
base = {
    "version": 2, "M": [[str(x) for x in row] for row in GENESIS_M_V2],
    "s_in": [str(x) for x in UNIFORM], "N": 1,
    "s_out": [str(x) for x in s1],
}
check("well-formed correct claim -> True", evaluate(dict(base)) is True)
wrong = dict(base); wrong["s_out"] = [str(s1[0]), str(s1[1]), str(s1[2] + 1)]
check("off-by-one WAD-unit claim -> False (invisible to v1's atol=1e-9)",
      evaluate(wrong) is False)
check("unknown version -> reject", evaluate(dict(base, version=3)) == "reject")
check("N > N_MAX -> reject", evaluate(dict(base, N=N_MAX + 1)) == "reject")
badsum = dict(base, s_in=[str(UNIFORM[0] - 1), str(UNIFORM[1]), str(UNIFORM[2])])
check("s_in sum != WAD -> reject", evaluate(badsum) == "reject")
badout = dict(base, s_out=[str(WAD + 1), "0", "0"])
check("claimed component > WAD -> reject (malformed, not False)",
      evaluate(badout) == "reject")

# --- INFORMATIVE: faithfulness to the live float64 v1 at N=2 (genesis M) ---
# Same shape as block_schema.compute_work, in plain IEEE-754 doubles (== float64).
M_F = [[0.70, 0.25, 0.05], [0.10, 0.75, 0.15], [0.20, 0.15, 0.65]]


def work_f64(s, n):
    out = list(s)
    for _ in range(n):
        out = [sum(M_F[i][j] * out[j] for j in range(3)) for i in range(3)]
    return out


worst = 0.0
hashes = [h_ones, "0x" + "deadbeef" * 8, "0x" + "07" * 8 + "c3" * 8 + "5a" * 8 + "00" * 8,
          "0x" + "ffffffffffffffff" + "0000000000000001" + "8000000000000000" + "00" * 8]
for h in hashes:
    si = derive_s(h)
    v2 = [x / WAD for x in work(GENESIS_M_V2, si, 2)]
    raw = bytes.fromhex(h[2:])
    a, b, c = (int.from_bytes(raw[k:k + 8], "big") for k in (0, 8, 16))
    t = a + b + c
    v1 = work_f64([a / t, b / t, c / t], 2)
    worst = max(worst, max(abs(x - y) for x, y in zip(v2, v1)))
check("INFORMATIVE: v2 within 1e-9 of float64 v1 at N=2 (worst |diff| = %.3g)" % worst,
      worst < 1e-9)

print()
print("%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
