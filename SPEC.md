# Markovian RESOLVE as an ERC-8004 Validation Method

**Status:** Draft profile · **Tag:** `markovian.resolve.v1` · **License:** Apache-2.0 (code), CC0 (spec text)

## Why this exists

ERC-8004's ValidationRegistry validates an agent's work with a 0–100 score from a
named validator. The EIP names four intended validator kinds — *stakers re-running
the job, zkML verifiers, TEE oracles, trusted judges* — but the ERC-8004 repo states
the validator-method section is **"still under active update and discussion with the
TEE community... revised and expanded in a follow-up spec update later this year."**
So the socket is defined; the plugs are not.

This profile defines a plug: **deterministic-replay validation**. It is a fourth kind
alongside the three the EIP sketches, and it removes the trust the other three retain.

| Validator kind | What you must trust |
|---|---|
| Staked re-execution | the economics (that ≥1 honest actor bothers to challenge) + a challenge window |
| zkML verifier | the prover pipeline + circuit; ~10³–10⁴× compute overhead |
| TEE oracle | the silicon vendor's enclave + attestation chain |
| **Markovian RESOLVE** | **nothing** — replay a committed pure function over committed public data; check the root against Bitcoin |

## What it validates

An agent's **outcome-claim**: a proposition over public data that becomes decidable at
or after a committed time / block height (e.g. *"asset X was in regime R at the 2026-06-29
close"*, *"metric M crossed T by block N"*). The claim is committed **before** the outcome
is knowable, so it cannot be backfilled.

## Mapping to `validationRequest` / `validationResponse`

```
validationRequest(
  validatorAddress = MarkovianResolutionValidator,
  agentId          = <IdentityRegistry NFT id of the agent under validation>,
  requestURI       = <proof bundle URL>,
  requestHash      = claimCommit            // Markovian claim/existence commitment (bytes32)
)

validationResponse(
  requestHash      = claimCommit,
  response         = 100 | 0,               // claim proven TRUE | FALSE (INDETERMINATE => void, not recorded)
  responseURI      = <proof bundle URL>,    // replayable proof (below)
  responseHash     = merkleRoot,            // deterministic-replay resolution root, Bitcoin-anchored
  tag              = "markovian.resolve.v1"
)
```

An agent opts in by listing `"markovian.resolve.v1"` in its ERC-8004 registration
`supportedTrust[]`. Consumers filter `getSummary(agentId, [validator], "markovian.resolve.v1")`.

## The proof bundle (served at `responseURI`)

```json
{
  "method": "deterministic_replay",
  "trustless": true, "arbiter": false, "oracle_vote": false, "committee": false,
  "resolved_state": "DISTRIBUTION",
  "confidence": 0.9998,
  "spec_id":       "…",   // hash of the resolution spec (the pure function's definition)
  "m_commitment":  "…",   // hash of the committed model/function M
  "merkle_root":   "…",   // == responseHash
  "attestation_hash": "…",
  "anchor": { "type": "opentimestamps->bitcoin",
              "ots": "https://…/verify/<merkle_root>.ots" },
  "attestation_ref": "…"  // the committed public inputs (bars/records) the replay runs over
}
```

## Verification procedure (what any third party runs)

1. Fetch `responseURI`.
2. Rerun the committed `M` (`m_commitment`) over the committed inputs (`attestation_ref`)
   under `spec_id`.
3. Rebuild the merkle root; assert it equals `responseHash`.
4. Confirm `responseHash` is timestamped in Bitcoin via the `.ots` proof (stock `ots verify`,
   zero Markovian trust).

If all four pass, the validation is real — regardless of what the validator contract,
the resolver, or anyone else says. **The referee is a pure function.**

## Relationship to the other registries

- **Identity**: the agent is an IdentityRegistry NFT; the validator is any address (no whitelist).
- **Reputation**: a stream of `markovian.resolve.v1` validations is objective, replayable input
  to reputation scoring — deterministic ground truth under the subjective feedback.
- **Complementary, not competing** with zkML/TEE validators: those prove an *inference was
  computed correctly*; this proves an *outcome-claim is true* against public data. An agent can
  carry both — a DeepProve/EigenAI proof that the model ran, and a Markovian resolution that the
  outcome resolved.
