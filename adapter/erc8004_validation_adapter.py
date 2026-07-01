#!/usr/bin/env python3
"""
erc8004_validation_adapter.py — envelope adapter #4 for the Verifiable Resolution
engine: map a Markovian ResolutionAttestation into an ERC-8004 ValidationRegistry
call pair (validationRequest + validationResponse).

Same philosophy as resolution_adapters.py: one engine, many envelopes. ERC-8004's
ValidationRegistry (v2.0.0) validates an agent's work with a 0-100 score from a
named validator. Its own spec says the validator-method section (zkML / TEE /
re-execution) is "still under active update" and undefined. Markovian RESOLVE is a
NEW validator type for that slot: DETERMINISTIC-REPLAY validation. Unlike a zkML
prover or a TEE oracle, the consumer does NOT have to trust the validator's answer
— the responseURI carries a replayable proof and the responseHash is Bitcoin-
anchored, so anyone re-runs the resolution and checks it themselves. It liberates
the referee.

Canonical ValidationRegistry (CREATE2, identical across 22 EVM chains):
  testnet  0x8004Cb1BF31DAf7788923b405b754f57acEB4272   (mainnet: not yet deployed)

validationResponse(bytes32 requestHash, uint8 response, string responseURI,
                   bytes32 responseHash, string tag)
"""
import os, sys, json, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import resolve_regime_milestone as engine

METHOD_TAG = "markovian.resolve.v1"          # goes in ERC-8004 `tag` + agent supportedTrust[]
VALIDATION_REGISTRY = "0x8004Cb1BF31DAf7788923b405b754f57acEB4272"
PROOF_BASE = "https://api.quantsynth.net/resolve/proof"   # returns the replayable attestation bundle

# Markovian verdict -> ERC-8004 score (0-100). Binary truth of the agent's claim;
# confidence + full state live in the proof bundle at responseURI.
_SCORE = {"PASS": 100, "FAIL": 0}            # INDETERMINATE -> void (not recorded on-chain)


def _b32(hexstr):
    """Normalize a 64-hex-char commitment to an 0x bytes32 literal."""
    h = hexstr[2:] if hexstr.startswith("0x") else hexstr
    if len(h) != 64:
        raise ValueError(f"expected 32-byte hex, got {len(h)//2} bytes")
    return "0x" + h


def to_erc8004_validation(agent_id, att, attestation_ref=None):
    """Map a Markovian ResolutionAttestation -> an ERC-8004 validation record:
    the exact on-chain call args (request + response) plus the off-chain proof
    bundle and the verify recipe. Ready for a validator contract or ethers script.
    Returns None for INDETERMINATE (void — nothing to assert on-chain)."""
    verdict = att["verdict"]
    if verdict not in _SCORE:
        return None  # INDETERMINATE: void, do not record a validation
    claim_commit = att["claim_commit"]
    merkle_root = att["root"]
    proof_uri = f"{PROOF_BASE}/{claim_commit}.json"
    ref = attestation_ref or os.path.join(engine.ATTEST, claim_commit + ".json")
    return {
        "erc8004": {
            "validationRegistry": VALIDATION_REGISTRY,
            "agentId": agent_id,
            # request commits the agent's claim being validated
            "validationRequest": {
                "validatorAddress": "<MarkovianResolutionValidator address>",
                "agentId": agent_id,
                "requestURI": proof_uri,
                "requestHash": _b32(claim_commit),      # the claim/existence commitment
            },
            # response records the trustless verdict
            "validationResponse": {
                "requestHash": _b32(claim_commit),
                "response": _SCORE[verdict],            # 100 = claim TRUE, 0 = claim FALSE
                "responseURI": proof_uri,               # replayable proof bundle
                "responseHash": _b32(merkle_root),      # Bitcoin-anchored resolution root
                "tag": METHOD_TAG,
            },
        },
        # off-chain proof bundle served at responseURI — what a verifier replays
        "proof": {
            "method": "deterministic_replay",
            "trustless": True, "arbiter": False, "oracle_vote": False, "committee": False,
            "resolved_state": att["resolved_state"],
            "confidence": att["conf"],
            "spec_id": att["spec"]["spec_id"],
            "m_commitment": att["m_commitment"],
            "merkle_root": merkle_root,
            "attestation_hash": att["attestation_hash"],
            "n_input_bars": len(att.get("bars", [])),
            "anchor": {"type": "opentimestamps->bitcoin", "status": att.get("ots_status"),
                       "ots": f"https://api.quantsynth.net/verify/{merkle_root}.ots"},
            "attestation_ref": ref,
        },
        "verify": (
            "Do NOT trust this validator's score. Fetch responseURI, rerun the committed "
            "M (m_commitment) over the committed bars (attestation_ref) under spec_id, rebuild "
            "the merkle root and check it equals responseHash. Confirm responseHash is "
            "timestamped in Bitcoin via the .ots proof. No database, no arbiter, no trust in "
            "the resolver — the referee is a pure function anyone can run."
        ),
    }


def resolve_agent_claim(agent_id, asset, proposition_state, resolution_time, created_at=None):
    """Resolve 'asset regime == proposition_state at resolution_time' trustlessly and
    emit the ERC-8004 validation record for the given agent NFT id."""
    if asset != engine.ASSET:
        raise ValueError(f"engine domain is {engine.ASSET}; got {asset}")
    cc, _, _ = engine.commit(proposition_state, resolution_time,
                             predictor_id=f"erc8004:agent:{agent_id}", commit_ts=created_at)
    att, path = engine.resolve(cc)
    return to_erc8004_validation(agent_id, att, attestation_ref=path)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    w = sub.add_parser("worked")
    f = sub.add_parser("from-att"); f.add_argument("--agent-id", required=True); f.add_argument("--att", required=True)
    a = ap.parse_args()
    if a.cmd == "from-att":
        att = json.load(open(a.att))
        print(json.dumps(to_erc8004_validation(a.agent_id, att, a.att), indent=2))
    else:
        rec = resolve_agent_claim("42", "QQQ", "DISTRIBUTION", "2026-06-29",
                                  created_at="2026-06-22T00:00:00Z")
        out = os.path.join(HERE, "worked_erc8004_validation.json")
        json.dump(rec, open(out, "w"), indent=2)
        print(json.dumps(rec, indent=2)); print("\nwrote", out)
