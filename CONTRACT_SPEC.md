# MarkovianResolutionValidator — Contract Spec (v2, proof-enforcing)

Decided 2026-07-09. Supersedes the EOA-as-validator demo: the proof-check moves **inside** the contract.

## Governing law
- Verdicts change **only by proof, never by authorship**. No admin/owner/upgrade key can write or rewrite a verdict.
- **Anchor the history, not the snapshot.** Every verdict (incl. supersessions) is appended, hash-linked; the log head is periodically frozen on Bitcoin.
- Bitcoin freezes the **claim** (what/when). Ethereum moves the **verdict** (what it means now). "Meant to change" never leaks into the claim layer.

## Placement
- Adopt ERC-8004 **Validation Registry** as the transport socket (canonical singleton on Base). Our contract is the `validatorAddress`.
- EAS optional as an additional consumer surface (resolver mirrors the same proof-gate). Not load-bearing.
- Deploy: Base Sepolia (flow already proven) → Base mainnet.

## Immutable wiring (set once at construction, then fixed)
```
IValidationRegistry immutable registry;   // canonical ERC-8004 on Base
IMarkovianVerifier   immutable verifier;   // on-chain proof checker
string  constant TAG = "markovian.resolve.v1";
```
No owner. No pause. No setter for `verifier` or `registry`. Rule is frozen; state is free to move.

## State
```
struct Entry {
  uint8   response;      // 100 = TRUE/PASS, 0 = FALSE/FAIL (INDETERMINATE = never written)
  bytes32 responseHash;  // Merkle/claim root (Bitcoin-anchored receipt)
  bytes32 inputCommit;   // pre-committed inputs hash (bound BEFORE outcome)
  bytes32 prevEntry;     // hash-link to previous entry for this request
  uint64  ts;
}
mapping(bytes32 => Entry[]) history;        // append-only per requestHash
mapping(uint256 => bytes32) head;           // per-agent log head (keccak chain)
mapping(bytes32 => bytes32) headAnchoredTo; // headHash -> Bitcoin commit ref
```

## Functions
**1. commitRequest(agentId, requestURI, requestHash, inputCommit)**
- Calls `registry.validationRequest(this, agentId, requestURI, requestHash)`.
- Stores `inputCommit`. `requestHash` immutable once set; self-validation blocked.
- **Pre-commitment clause:** `inputCommit` must be set here, before any response — else an operator could pick inputs after seeing the desired output. Reverts a response if absent.

**2. recordResolution(requestHash, response, responseURI, responseHash, proof)** — the gate
```
require(request exists && inputCommit set);
require(verifier.verify(requestHash, inputCommit, response, responseHash, proof), "PROOF");
// ^ authorization IS the proof — no msg.sender==validatorKey trust
append Entry{..., prevEntry: head[agentId]};
head[agentId] = keccak256(head[agentId], entryHash);   // append-only chain
registry.validationResponse(requestHash, response, responseURI, responseHash, TAG);
emit ResolutionRecorded(requestHash, response, responseHash, head[agentId]);
```
- Supersession = a *new valid proof* for the same requestHash with new evidence → appends a new Entry. Never deletes. Mutable verdict, proof-gated.

**3. anchorHead(agentId, headHash, btcCommitRef)**
- Records that `headHash` was committed to Bitcoin (OTS proof / OP_RETURN txid ref).
- Makes "it changed" tamper-evident: the append-only head is periodically frozen on Bitcoin (weekly, mirrors `btc_anchor.py` cadence).
- The ref is verifiable off-chain against Bitcoin, so it adds no trust.

**Views:** `getLatest(requestHash)`, `getHistory(requestHash)`, `getHead(agentId)`, `headAnchoredTo(headHash)`.

## IMarkovianVerifier
```
function verify(bytes32 requestHash, bytes32 inputCommit,
                uint8 response, bytes32 responseHash,
                bytes calldata proof) external view returns (bool);
```
- Impl A (ship first): Pedersen `C=r·G+m·H` + Schnorr (Fiat-Shamir) binding check over BN128, ~tens of k gas. Verifies the commitment binding; deterministic replay attested off-chain at `responseURI`.
- Impl B (upgrade): full SNARK verifier for `s_out = M·Tᴺ·s_in`, ~200k gas, batch/amortize.
- Verifier is immutable per deployment; upgrading = deploy a new validator, not mutate this one.

## Verification cost model — DECIDED (b), 2026-07-09
Every `recordResolution` verifies the cheap Impl-A binding (Pedersen+Schnorr, ~tens of k gas). The full SNARK (Impl B, `s_out=M·Tᴺ·s_in`) is required **only on challenge**.
- A challenge is settled by **recomputation**, not a vote. No dispute committee, no optimistic-trust window in the social sense — the full proof either verifies or it doesn't.
- `challenge(requestHash, entryIndex)` opens a slot; `resolveChallenge(..., snarkProof)` requires `verifier.verifyFull(...)` to pass or the entry is marked FAILED (and, if staking is added later, slashed).
- Rationale: replay is deterministic and evidence is public, so the expensive proof is only needed when someone actually disputes — cost scales with contention, not volume.

## Not in scope (by design)
No owner, no admin verdict path, no pause, no upgrade key over verdicts. The only "governance" is the choice of verifier at construction, then renounced by immutability.

## Proof binding (Impl A) — exact byte-packing (normative)

This section pins the bytes so the spec, the vectors, the Solidity verifier, and every
independent reimplementation agree. Conformance is defined against `vectors/vectors.json`.

### Curve
- `alt_bn128` (BN254) G1. Field modulus `p = 21888242871839275222246405745257275088696311157297823662689037894645226208583`.
- Group order `n = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
- Generator `G = (1, 2)`. Cofactor 1: every on-curve G1 point is a group element.

### Second generator H (nothing-up-my-sleeve)
- Seed: `"MarkovianPedersenH/v1"` (UTF-8, no terminator).
- Derivation: try-and-increment. For `ctr = 0, 1, 2, ...`, set
  `x = uint256(keccak256(seed || ctr_be32)) mod p`. Accept the first `ctr` where `x^3 + 3`
  is a quadratic residue mod `p`. Take the square root and canonicalize to even `y`.
- Result: `ctr = 1`,
  `Hx = 5377175913649479379263465455642277271589943785262235518488102493446694764727`,
  `Hy = 18582477386614225867917162748664838381101259733110968402388124672615493937444`.
- The deployed `SchnorrPedersenVerifier` is constructed with exactly this `Hx, Hy`. `H`
  has no known discrete log to `G`; no party can open a commitment two ways.

### Context and challenge
```
context = keccak256( requestHash[32] || inputCommit[32] || response[uint8 = 1 byte] || responseHash[32] )   // abi.encodePacked
e       = uint256( keccak256( Rx[32] || Ry[32] || Cx[32] || Cy[32] || context[32] ) ) mod n
```
Each coordinate is a 32-byte big-endian word. `response` is a single byte. The challenge
binds the verdict tuple into the proof, so a proof for one `(response, responseHash)` cannot
be replayed onto another.

### Check
```
s_m*G + s_r*H == R + e*C        over alt_bn128 G1
```
A write is authorized iff this holds. There is no `msg.sender == validatorKey` path: the proof
is the authorization.

### Proof encoding and the reserved version byte
- Version 1 (current): `proof = abi.encode(uint256 Cx, uint256 Cy, uint256 Rx, uint256 Ry, uint256 s_m, uint256 s_r)`.
- A leading version byte is reserved for future layouts. All current vectors are version 1.
- Forward-compatibility rule: an unknown version, an unknown tag, or a `response` outside the
  defined verdict domain MUST be rejected cleanly. A conformant verifier returns a reject
  classification and never crashes, and never silently treats a malformed input as a passing or
  failing equation.

### Verdict domain
- `0 = FALSE`, `100 = TRUE`. `INDETERMINATE` is never written. Any `response` outside `{0, 100}`
  is reserved and MUST be rejected cleanly (see the `grease-reserved-response` vector).

### Conformance
- Vectors: `vectors/vectors.json` (derived byte-exact from the Base Sepolia deployment).
- Reference verifiers: `verifier/verify_vectors.py` (py_ecc) and `goverify/` (pure math/big alt_bn128, no external curve lib). Both
  reproduce every `expect`, and they agree vector-for-vector. Reimplement the check in any
  language and pass the same file.
