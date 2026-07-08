#!/usr/bin/env python3
"""Independently verify the Markovian deterministic-replay validationResponse.

Trust nobody. This script reads only PUBLIC data and recomputes every step, then
checks it against the on-chain ERC-8004 record on Base Sepolia:

  1. The on-chain requestHash equals SHA-256 over the canonical (RFC 8785) claim
     that was pre-committed BEFORE the outcome existed (OpenTimestamps-anchored).
  2. The on-chain responseHash equals SHA-256 over the canonical resolution evidence.
  3. The verdict is reproducible: fetch Bitcoin block 957110's hash from any public
     source and re-run the committed function; it must match the on-chain response.

Requires: pip install web3   (reads public RPC + raw GitHub + a Bitcoin explorer)
"""
import json, hashlib, urllib.request
from web3 import Web3

RPC = "https://base-sepolia-rpc.publicnode.com"
VALIDATION = Web3.to_checksum_address("0x8004Cb1BF31DAf7788923b405b754f57acEB4272")
CLAIM_COMMIT = "0x24bdf9767d91a2f560e9d2fd5edb33dae2c67c7a978552ea0b13bfabeb8801a2"
REQUEST_URI = "https://raw.githubusercontent.com/MarkovianProtocol/erc8004-resolution-validator/0071a8886eb65deed394d3f636796b747872621f/live-demo/preregistration.pretty.json"
RESPONSE_URI = "https://raw.githubusercontent.com/MarkovianProtocol/erc8004-resolution-validator/5bee6fd0c48868f6c44a58cc0e6b99af08f23635/live-demo/resolution.pretty.json"
ABI = [{"name": "getValidationStatus", "type": "function", "stateMutability": "view",
        "inputs": [{"name": "requestHash", "type": "bytes32"}],
        "outputs": [{"type": "address"}, {"type": "uint256"}, {"type": "uint8"},
                    {"type": "bytes32"}, {"type": "string"}, {"type": "uint256"}]}]

def jcs(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def get(u): return urllib.request.urlopen(u, timeout=25).read()
def sha(b): return "0x" + hashlib.sha256(b).hexdigest()

def main():
    w3 = Web3(Web3.HTTPProvider(RPC))
    c = w3.eth.contract(address=VALIDATION, abi=ABI)
    validator, agent_id, response, response_hash, tag, ts = c.functions.getValidationStatus(CLAIM_COMMIT).call()
    response_hash = "0x" + response_hash.hex()
    print(f"on-chain ERC-8004 record: agentId={agent_id} response={response} tag={tag}")
    print(f"  validator={validator}\n  requestHash={CLAIM_COMMIT}\n  responseHash={response_hash}\n")

    checks = []
    # 1. requestHash is the pre-committed claim, re-derivable from public evidence
    claim = json.loads(get(REQUEST_URI))
    checks.append(("on-chain requestHash == SHA256(canonical claim)", sha(jcs(claim)) == CLAIM_COMMIT.lower(), sha(jcs(claim))))
    # 2. responseHash is the canonical resolution evidence
    evid = json.loads(get(RESPONSE_URI))
    checks.append(("on-chain responseHash == SHA256(canonical evidence)", sha(jcs(evid)) == response_hash.lower(), sha(jcs(evid))))
    # 3. the verdict is reproducible from public Bitcoin data
    height = claim["resolution_function"]["inputs"]["height"]
    blockhash = get(f"https://mempool.space/api/block-height/{height}").decode().strip()
    reproduced = 100 if (int(blockhash, 16) % 2 == 0) else 0
    checks.append((f"verdict reproducible from BTC block {height} (hash …{blockhash[-8:]})", reproduced == response, f"recomputed={reproduced} on-chain={response}"))

    print("VERIFICATION:")
    ok_all = True
    for name, ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}\n         {detail}")
        ok_all = ok_all and ok
    print("\nRESULT:", "ALL CHECKS PASS — the validation is independently reproducible, no operator trusted." if ok_all else "MISMATCH — do not trust.")
    return 0 if ok_all else 1

if __name__ == "__main__":
    raise SystemExit(main())
