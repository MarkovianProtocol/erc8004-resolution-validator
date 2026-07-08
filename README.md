# erc8004-resolution-validator

**A deterministic-replay validator for the [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) ValidationRegistry.**

ERC-8004 gives agents an on-chain trust layer: Identity, Reputation, and Validation
registries. Identity and Reputation shipped. The **Validation** registry — the part that
makes "trustless" mean something — is still open: the spec says the validator-method
section is *"under active update with the TEE community, revised later this year,"* and
names only *stakers re-running the job, zkML verifiers, TEE oracles, trusted judges*.

This repo contributes a fourth validator kind that needs **no stake, no committee, no
enclave**: **Markovian RESOLVE**. It settles an agent's outcome-claim by replaying a
committed pure function over committed public data, and anchors the result to Bitcoin
via OpenTimestamps. A consumer verifies by re-running the replay themselves — they never
trust the validator.

## Contents

| File | What it is |
|---|---|
| `SPEC.md` | The `markovian.resolve.v1` validation-method profile (request/response mapping, proof bundle, verification procedure). |
| `contracts/MarkovianResolutionValidator.sol` | The validator contract. Records a resolution into the canonical ValidationRegistry. |
| `adapter/erc8004_validation_adapter.py` | Maps a live Markovian ResolutionAttestation → the exact ERC-8004 call args + off-chain proof bundle. |
| `examples/worked_erc8004_validation.json` | A worked resolution (series-a state, deterministic replay over 6,661 committed records, Bitcoin-anchored) mapped to a `validationResponse`. |

## The one idea

Every other validator type leaves a residue of trust — in a prover, a chip vendor, or an
economic majority. Deterministic replay leaves none:

```
Don't trust the score. Fetch responseURI. Rerun the committed M over the committed
inputs. Rebuild the merkle root. Check it equals responseHash. Check responseHash is
in Bitcoin (stock `ots verify`). The referee is a pure function anyone can run.
```

The claim is committed **before** the outcome is knowable (existence-predates-outcome),
so it cannot be backfilled; the root is in Bitcoin, so its timing is not the validator's
word. This is the ERC-8004 Validation registry's missing objective ground truth.

## Complements, does not compete

zkML (DeepProve) and TEE re-execution (EigenAI) prove *an inference was computed correctly*.
Markovian RESOLVE proves *an outcome-claim is true against public data*. An agent can carry
both. This validator is the settlement layer under the reputation score.

## Status

Reference profile + working adapter + validator contract. Not yet deployed to the
ValidationRegistry (mainnet ValidationRegistry itself is not yet deployed; testnet at
`0x8004Cb1BF31DAf7788923b405b754f57acEB4272`). Built to inform the open validator-method
spec discussion. Apache-2.0 (code) / CC0 (spec text).
