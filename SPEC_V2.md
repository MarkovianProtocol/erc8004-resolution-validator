# Markovian Work Function v2 — Integer Profile

**Status:** Draft profile · **Tag:** `markovian.resolve.v2` · **License:** Apache-2.0 (code), CC0 (spec text)

## Why this exists

The committed claim function of the live chain is `s_N = M^N · s` in float64, and replay
compares with `np.allclose(atol=1e-9)`. That has two defects for deterministic replay:

1. **Tolerance is not determinism.** Two honest implementations can produce results that
   differ within the tolerance band, so "replay and compare" admits a gray zone — the one
   thing a deterministic-replay validator must not have. Worse, a forged output that is
   wrong by less than `1e-9` *passes*.
2. **Floats cannot run in the EVM.** The on-chain challenge path (`verifyFull`) can never
   recompute a float64 claim natively.

v2 restates the same function over WAD fixed-point integers with an exact-equality verdict.
Every conforming implementation — Python, Go, Solidity, anything else — produces the same
bytes or it is wrong. There is no tolerance parameter to disagree about.

**Scope.** v2 is a profile of this validator repo only. The live MKV chain is float64 v1
and continues to validate its own history unchanged; v2 changes nothing in the consensus
path. `markovian.resolve.v1`'s proof-binding layer (CONTRACT_SPEC.md) is orthogonal and
also unchanged: v2 replaces only the *work function* that deterministic replay recomputes.

## Values and constants (normative)

| Constant | Value | Meaning |
|---|---|---|
| `WAD` | `10^18` | fixed-point scale; all values are WAD-scaled unsigned 256-bit integers |
| `N_MAX` | `2^20` (1,048,576) | upper bound on iterations; `N > N_MAX` MUST be rejected |
| version | `2` | unknown versions MUST be rejected cleanly (never crashed on, never coerced) |

**GENESIS_M v2** is the exact WAD image of the two-decimal float64 genesis matrix —
`0.70 → 700000000000000000`, exact, no rounding anywhere:

```
[ 700000000000000000  250000000000000000   50000000000000000 ]   // from S0
[ 100000000000000000  750000000000000000  150000000000000000 ]   // from S1
[ 200000000000000000  150000000000000000  650000000000000000 ]   // from S2
```

Every row of GENESIS_M v2 sums to **exactly** `WAD`. This is a REQUIREMENT on any v2
matrix (governance updates included): an entry above `WAD` or a row sum other than `WAD`
is malformed → reject. Row sums being exact is what bounds every reachable state
component at `WAD` (see the overflow analysis) — it is load-bearing, not cosmetic.

## State vectors (normative)

A state vector `s` is three WAD-scaled unsigned integers. For an **input** vector:

- every component MUST satisfy `s[i] ≤ WAD`;
- the components MUST sum to **exactly** `WAD`.

Anything else is malformed → reject (never silently normalized, never a false verdict).

Claimed **output** vectors are not sum-constrained (see "No renormalization"), but every
component MUST still be `≤ WAD`: no reachable output has a component above `WAD`, so a
claim outside that domain is malformed → reject, not false.

## Input derivation (normative)

v1 derives `s` from a block hash as "first 24 bytes as 3 big-endian uint64, normalized".
Integerized:

```
a = uint64_be(hash[0:8]);  b = uint64_be(hash[8:16]);  c = uint64_be(hash[16:24])
total = a + b + c
if total == 0: reject                       // v1 divides by zero here; v2 pins the reject
s[i]  = floor(x_i * WAD / total)            // x = (a, b, c)
r     = WAD - (s[0] + s[1] + s[2])          // r ∈ {0, 1, 2}
s[0] += r                                   // REMAINDER RULE: all leftover WAD-units to index 0
```

The remainder rule is normative: floor division loses up to 2 WAD-units across the three
components; they are added to **index 0**, making the sum exactly `WAD`. (Any fixed rule
would do; index 0 is the pinned choice. Nearest-rounding is NON-conformant — see the
`derive-remainder-2` vector, where it produces a different vector.) `s[0]` cannot exceed
`WAD`: `s[0] = WAD` requires `b = c = 0`, which makes `r = 0`.

## The iteration (normative)

One iteration is the matvec with **per-element floor, then sum**:

```
s'[i] = floor(M[i][0]*s[0] / WAD) + floor(M[i][1]*s[1] / WAD) + floor(M[i][2]*s[2] / WAD)
```

Floor each of the three products separately, then add. This is NOT the same as flooring
the summed row product once; the per-term form is pinned because it is the standard WAD
`mulDown` primitive — implementations compose from audited fixed-point building blocks,
and native EVM division is exactly this floor.

`s_N` is `N` applications of this step by **plain loop**. `N = 0` is the identity
(`s_out = s_in`).

**No renormalization.** The iteration never rescales. Note that `M` is row-stochastic and
acts on a *column* vector, so the component **sum is not preserved** even in exact
arithmetic (columns of GENESIS_M sum to 1.00 / 1.15 / 0.85 WAD) — this is a property of
the committed v1 function, faithfully carried over, not a v2 artifact. Floor rounding
additionally drops up to 3 WAD-units per iteration. None of this is "drift" to be
corrected: the verdict is exact equality of the final 3-vector, and every conforming
implementation loses the identical units in the identical places.

**Exponentiation-by-squaring is excluded — NON-conformant.** Floored matrix products are
non-associative: `floor(floor(M·M)·s)` and `floor(M·floor(M·s))` differ in general, so a
squaring implementation computes a *different function* and there is no rounding schedule
that reconciles the two. `N ≤ N_MAX` keeps the plain loop cheap everywhere (a 3×3 integer
matvec, ≤ 2^20 times), so the simplest rule is also the safe one: **plain iteration is
the only conformant evaluation order.**

**Bound on N.** `N_MAX = 2^20`, chosen to cap verification work with wide headroom over
the live chain (`difficulty_n = 1000` at genesis and today). `N > N_MAX` → reject, before
any iteration runs. *(Informative: measured on py-evm via solc 0.8.35 `--via-ir
--optimize`, `verifyWorkGenesis` costs 37,755 gas at N=2 and 357,845 gas at N=1000 —
~321 gas marginal per iteration, extrapolating to ~336M gas at N_MAX. So N above roughly
10^5 exceeds a ~36M-gas Ethereum block; a challenge at extreme N settles via `eth_call` /
off-chain replay of the same pure function, or a future SNARK — the bound caps
computation, it does not promise single-block on-chain execution at every N.)*

## The verdict (normative)

```
verify(M, s_in, N, s_out_claimed)  =  ( work(M, s_in, N) == s_out_claimed )
```

**Exact equality of all three components. No tolerance, no epsilon, no allclose.** A
claim off by one WAD-unit (10^-18) is FALSE — the `wrong-output-one-unit` vector pins
exactly the forgery that v1's `atol=1e-9` accepts.

## Gate order and the reject class (normative)

Checked before any arithmetic, in this order: **version → N → matrix → derivation →
s_in → s_out_claimed**. Every gate failure classifies as `reject` — cleanly, never a
crash, and never silently coerced into a true/false verdict. In Solidity the reject class
is a **typed revert** (`NTooLarge`, `MatrixMalformed`, `StateComponentTooLarge`,
`StateSumInvalid`, `DerivationUndefined`); the version gate is the deployment itself — a
different profile version is a different contract.

## Overflow analysis (normative statement, informative proof)

All arithmetic fits uint256 with no intermediate overflow:

- Derivation: `x_i < 2^64`, `WAD < 2^60` ⇒ `x_i·WAD < 2^124`.
- Iteration: every `M[i][j] ≤ WAD` and every `s[j] ≤ WAD` ⇒ each product
  `≤ WAD² = 10^36 < 2^120 ≪ 2^256`; each new component `≤ Σ_j M[i][j]·max(s)/WAD =
  max(s)` because rows sum to exactly `WAD` — **the maximum component never grows**, so
  `s[j] ≤ WAD` is an invariant for every `N`, and the loop is safe unchecked.
- Sums of ≤ 3 values `≤ WAD` (checks) or `≤ WAD` quotients (matvec) stay under `2^62`.

## Faithfulness to v1 (informative, NOT a conformance requirement)

For the genesis matrix at the live difficulty, v2's WAD result converted to float agrees
with the float64 v1 computation to well under `1e-9` (measured worst |diff| ≈ `6e-17` at
`N = 2` across live block-hash-derived inputs — see `verifier/test_workfn_v2.py`). This
sanity-checks that the integerization is faithful; conformance is defined ONLY by exact
equality on the vectors, never by proximity to float64.

## Conformance

Vectors: [`vectors/vectors_v2.json`](vectors/vectors_v2.json) — `expect: true | false |
reject`, including derivation-from-hash vectors (live MKV block hashes; the remainder
rule firing at its maximum r=2), the one-WAD-unit forgery that v1 tolerance accepts, and
grease (wrong sum, component > WAD, unknown version, N > N_MAX, zero derivation,
malformed matrix).

Reference implementations, all of which reproduce every vector byte-exactly:

- [`verifier/workfn_v2.py`](verifier/workfn_v2.py) — pure stdlib Python (tests:
  `verifier/test_workfn_v2.py`);
- [`goverify/workv2.go`](goverify/workv2.go) — math/big Go (`go test` in `goverify/`);
- [`contracts/MarkovianWorkV2.sol`](contracts/MarkovianWorkV2.sol) — Solidity, executed
  as real EVM bytecode by [`contracts/test_workv2_evm.py`](contracts/test_workv2_evm.py)
  (solc + py-evm), typed reverts for the reject class, measured gas.

Reimplement the function in any language and pass the same file. Point to where it breaks.
