#!/usr/bin/env python3
"""Independently verify the meaningful deterministic-replay validationResponse (throughput claim).
Reads only PUBLIC data and recomputes every step, checked against the on-chain ERC-8004 record on
Base Sepolia. Requires: pip install web3."""
import json, hashlib, urllib.request
from web3 import Web3

RPC = "https://base-sepolia-rpc.publicnode.com"
VALIDATION = Web3.to_checksum_address("0x8004Cb1BF31DAf7788923b405b754f57acEB4272")
CLAIM_COMMIT = "0xa20e6aec5035dd1884288d295b0e997a4aa24eba3c377c2aec15236811c41c3b"
REQUEST_URI = "https://raw.githubusercontent.com/MarkovianProtocol/erc8004-resolution-validator/075eabb712372509a8326695f027a6f81c578a68/live-demo-2/preregistration.pretty.json"
RESPONSE_URI = "https://raw.githubusercontent.com/MarkovianProtocol/erc8004-resolution-validator/352343b39ce5e89597147198d37509dcf8a7d9b6/live-demo-2/resolution.pretty.json"
ABI = [{"name": "getValidationStatus", "type": "function", "stateMutability": "view",
        "inputs": [{"name": "requestHash", "type": "bytes32"}],
        "outputs": [{"type": "address"}, {"type": "uint256"}, {"type": "uint8"}, {"type": "bytes32"}, {"type": "string"}, {"type": "uint256"}]}]

def jcs(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def get(u): return urllib.request.urlopen(u, timeout=25).read()
def sha(b): return "0x" + hashlib.sha256(b).hexdigest()

def main():
    w3 = Web3(Web3.HTTPProvider(RPC))
    c = w3.eth.contract(address=VALIDATION, abi=ABI)
    validator, agent_id, response, response_hash, tag, ts = c.functions.getValidationStatus(CLAIM_COMMIT).call()
    response_hash = "0x" + response_hash.hex()
    print(f"on-chain ERC-8004 record: agentId={agent_id} response={response} tag={tag}")
    print(f"  requestHash={CLAIM_COMMIT}\n  responseHash={response_hash}\n")

    claim = json.loads(get(REQUEST_URI))
    evid = json.loads(get(RESPONSE_URI))
    height = claim["resolution_function"]["inputs"]["height"]
    thr = claim["resolution_function"]["inputs"]["threshold"]
    bh = get(f"https://mempool.space/api/block-height/{height}").decode().strip()
    txc = int(json.loads(get(f"https://mempool.space/api/block/{bh}"))["tx_count"])
    reproduced = 100 if (txc > thr) else 0

    checks = [
        ("on-chain requestHash == SHA256(canonical claim)", sha(jcs(claim)) == CLAIM_COMMIT.lower(), sha(jcs(claim))),
        ("on-chain responseHash == SHA256(canonical evidence)", sha(jcs(evid)) == response_hash.lower(), sha(jcs(evid))),
        (f"verdict reproducible from BTC block {height} (tx_count={txc} > {thr})", reproduced == response, f"recomputed={reproduced} on-chain={response}"),
    ]
    print("VERIFICATION:")
    ok_all = True
    for name, ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}\n         {detail}")
        ok_all = ok_all and ok
    print("\nRESULT:", "ALL CHECKS PASS - independently reproducible, no operator trusted." if ok_all else "MISMATCH - do not trust.")
    return 0 if ok_all else 1

if __name__ == "__main__":
    raise SystemExit(main())
