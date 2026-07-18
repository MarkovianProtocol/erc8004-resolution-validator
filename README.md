# erc8004-resolution-validator

**A deterministic-replay validator for the [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) ValidationRegistry: a verdict is written only when a proof verifies, and any third party can reproduce the proof with no trusted party in the loop.**

ERC-8004 gives agents an on-chain trust layer of three registries: Identity, Reputation,
and Validation. The Validation registry is the open one. Its own spec names only
*stakers re-running the job, zkML verifiers, TEE oracles, trusted judges*, and states the
validator-method section is under active revision. Each of those kinds leaves a residue of
trust: an economic majority, a prover pipeline, or a silicon vendor's enclave.

This repository contributes a fourth kind, **Markovian RESOLVE**, that leaves none. It
settles an agent's outcome-claim by replaying a committed pure function over committed
public data, binds the verdict on-chain with a Pedersen+Schnorr proof, and anchors the
result to Bitcoin. No stake. No committee. No enclave. No operator is trusted.

## Run it

```bash
git clone https://github.com/MarkovianProtocol/erc8004-resolution-validator
cd erc8004-resolution-validator

# 1. Conformance vectors. Pure crypto, no network, no chain.
#    Recomputes the challenge and checks s_m*G + s_r*H == R + e*C for every vector.
pip install py_ecc eth-utils
python verifier/verify_vectors.py vectors/vectors.json

# 2. Independent verification against the LIVE Base Sepolia deployment.
#    Reads only public RPC + published artifacts; reproduces every accepted verdict
#    and shows the tampered proof failing the exact equation the chain rejected.
pip install web3
python live-demo-v2/verify.py

# 3. Second, independent verifier in Go. Same vectors, must agree with Python.
cd goverify && go run . ../vectors/vectors.json
```

## Click the proofs (Base Sepolia)

The demo ran three writes against the deployed contracts. The middle one was a tampered
proof; the chain reverted it. Everything below is on-chain and replayable.

| Event | Result | Transaction |
|---|---|---|
| Record entry0 (verdict FALSE) | accepted, log length 1 | [`0x0dd8d0b4…`](https://sepolia.basescan.org/tx/0x0dd8d0b4873bfe066480e848db24eb9070cd5719dfa74d75e194e6d3c4097b0d) |
| Tampered write (entry0 proof, response flipped 0→100) | **reverted `ProofInvalid()`** | [`0x62181568…`](https://sepolia.basescan.org/tx/0x62181568701156ae9bb87be9c392517285026e250227e116a92dddbf9e2221a0) |
| Record entry1 (verdict TRUE, supersedes via new proof) | accepted, hash-linked, log length 2 | [`0x93a3919439…`](https://sepolia.basescan.org/tx/0x93a3919439c79a01d88e06af712224b5c5a1754f5c9de8358386bf0e7e1fdb43) |

| Contract | Address |
|---|---|
| MarkovianResolutionValidator | [`0xef4d03f39ee93027eDBbfeDb65AE92662122A6a5`](https://sepolia.basescan.org/address/0xef4d03f39ee93027eDBbfeDb65AE92662122A6a5) |
| SchnorrPedersenVerifier | [`0xd6cD446E2c2C8326aA040C502380AEdB42e0d1A0`](https://sepolia.basescan.org/address/0xd6cD446E2c2C8326aA040C502380AEdB42e0d1A0) |
| ERC-8004 ValidationRegistry | [`0x8004Cb1BF31DAf7788923b405b754f57acEB4272`](https://sepolia.basescan.org/address/0x8004Cb1BF31DAf7788923b405b754f57acEB4272) |

Chain 84532, agentId 7816.

## The one idea

Authorization is the proof, not the author. The validator writes a verdict only if a
Pedersen commitment opening, bound through a Fiat-Shamir challenge to the exact
`(requestHash, inputCommit, response, responseHash)` tuple, verifies on alt_bn128 G1. No
proof means no write, and no owner, admin, or upgrade key can substitute for one. A proof
built for one verdict cannot be replayed onto another, which is exactly why the tampered
transaction above reverted.

Underneath the on-chain gate sits the off-chain settlement: fetch `responseURI`, rerun the
committed function over the committed inputs, rebuild the Merkle root, check it equals
`responseHash`, and check `responseHash` is timestamped in Bitcoin with stock `ots verify`.
The claim is committed before the outcome is knowable, so it cannot be backfilled. The
referee is a pure function anyone can run.

## Conformance

`vectors/vectors.json` is the conformance surface, derived byte-exact from the deployment
above. Each vector carries the curve parameters, the verdict tuple, the proof, and an
`expect` of `true`, `false`, or `reject`. Two reference verifiers reproduce every `expect`
and agree vector-for-vector:

- `verifier/verify_vectors.py`: py_ecc, standalone, no chain.
- `goverify/`: Go over alt_bn128 G1 in pure `math/big` (no external curve lib), same file, same results.

Reimplement the verifier in your language and pass `vectors/vectors.json`. The exact
byte-packing of the context, the challenge, and the nothing-up-my-sleeve generator `H` is
normative in [`CONTRACT_SPEC.md`](CONTRACT_SPEC.md). A leading version byte is reserved:
an unknown version, an unknown tag, or a `response` outside the verdict domain `{0, 100}`
must be rejected cleanly, never crash. The grease vectors exercise that rule.

**Point to where it breaks.**

## Scope

Honest boundaries of what is deployed:

- Network is Base Sepolia testnet. The mainnet ValidationRegistry is not yet deployed by
  ERC-8004; this validator is built to inform the open validator-method discussion.
- The binding proof (Impl A, Pedersen+Schnorr, ~tens of k gas) is checked on **every**
  write. That is the gate demonstrated on-chain above.
- The full-computation SNARK (Impl B, `verifyFull`, proving `s_out = M·Tᴺ·s_in`) settles a
  **challenge**, and is **not yet wired**. `verifyFull` reverts `IMPL_B_PENDING` rather than
  pretend. Until it lands, a challenge cannot be settled on-chain. Cost scales with
  contention: the cheap binding runs always, the expensive proof runs only on dispute.

## Contents

| Path | What it is |
|---|---|
| `SPEC.md` | The `markovian.resolve.v1` validation-method profile: request/response mapping, proof bundle, verification procedure. |
| `CONTRACT_SPEC.md` | The v2 proof-enforcing contract spec and the normative proof byte-packing. |
| `contracts/` | `IMarkovianVerifier.sol`, `SchnorrPedersenVerifier.sol` (Impl A), `MarkovianResolutionValidator.sol`. |
| `vectors/vectors.json` | Conformance test vectors, byte-exact from the Base Sepolia deployment. |
| `verifier/verify_vectors.py` | Standalone Python verifier (py_ecc). |
| `goverify/` | Standalone Go verifier (pure math/big alt_bn128). Same vectors, must agree. |
| `live-demo-v2/` | The live Base Sepolia demo: prover, independent verifier, claim/evidence artifacts, on-chain state. |
| `adapter/` | Maps a Markovian ResolutionAttestation to the exact ERC-8004 call args plus the off-chain proof bundle. |

## Relationship to zkML and TEE validators

zkML (for example DeepProve) and TEE re-execution (for example EigenAI) prove that *an
inference was computed correctly*. Markovian RESOLVE proves that *an outcome-claim is true
against public data*. The two compose: an agent can carry a proof that its model ran and a
Markovian resolution that the outcome resolved. This validator is the settlement layer
under a reputation score.

## Live on mainnet (2026-07-17)

The agent behind this work is registered on the canonical ERC-8004 Identity Registry on
Base mainnet as agent [`eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432/59270`](https://basescan.org/nft/0x8004a169fb4a3325136eb29fa0ceb6d2e539a432/59270),
declaring the trust model `witnessed-log`. Its [registration file](https://markovianprotocol.com/.well-known/sigmasynth-registration.json)
lists a C2SP checkpoint endpoint cosigned by seven independent witnesses, machine-readable,
and a [browser-side verifier](https://markovianprotocol.com/trace.html) checks every
cosignature in-page. A claim this validator settles can be published as an ERC-8004
artifact file whose on-chain bytes32 is keccak256 of the exact served bytes, embedded log
coordinates included, so verification walks from the hash to a witnessed checkpoint with
no trusted party.

Apache-2.0 (code) / CC0 (spec text).
