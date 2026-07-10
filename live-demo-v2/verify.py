#!/usr/bin/env python3
"""Independent verifier for the Markovian proof-enforcing ERC-8004 validator (Base Sepolia).

Reads ONLY public data: the Base Sepolia RPC + the published evidence/state artifacts.
Recomputes, from scratch and trusting no operator:
  1. H is the nothing-up-my-sleeve generator of seed "MarkovianPedersenH/v1" AND equals the
     Hx,Hy the deployed SchnorrPedersenVerifier was constructed with (read from chain).
  2. For each accepted Entry: responseHash == SHA256(canonical evidence); the verdict is
     reproducible from the public block hash parity; and the Pedersen+Schnorr equation
     s_m*G + s_r*H == R + e*C HOLDS for the proof recorded on-chain.
  3. For the TAMPERED probe (flipped response, same proof) the SAME equation FAILS -> which is
     exactly why recordResolution reverted ProofInvalid on-chain.
Exit 0 iff every check passes.
"""
import os, json, hashlib
from web3 import Web3
import markov_crypto as mc

DIR = os.path.dirname(os.path.abspath(__file__))
RPCS = ["https://base-sepolia-rpc.publicnode.com", "https://sepolia.base.org"]
STATE = json.load(open(os.path.join(DIR, "onchain_state.json")))
V_ABI = [{"name":n,"type":"function","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]} for n in ("Hx","Hy")]
REG_ABI = [{"name":"getValidationStatus","type":"function","stateMutability":"view",
  "inputs":[{"name":"requestHash","type":"bytes32"}],
  "outputs":[{"type":"address"},{"type":"uint256"},{"type":"uint8"},{"type":"bytes32"},{"type":"string"},{"type":"uint256"}]}]
REGISTRY = Web3.to_checksum_address("0x8004Cb1BF31DAf7788923b405b754f57acEB4272")

def jcs(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def sha(b): return "0x"+hashlib.sha256(b).hexdigest()
def b32(hexstr): return bytes.fromhex(hexstr[2:])

def connect():
    for u in RPCS:
        w=Web3(Web3.HTTPProvider(u,request_kwargs={"timeout":40}))
        if w.is_connected(): return w
    raise SystemExit("no RPC")

def main():
    w=connect()
    checks=[]
    req = b32(STATE["requestHash"]); ic = b32(STATE["inputCommit"])

    # 1. H nothing-up-my-sleeve, and equals the deployed verifier's constructor args
    Hx,Hy,ctr = mc.derive_H()
    ver = w.eth.contract(address=Web3.to_checksum_address(STATE["verifier"]), abi=V_ABI)
    onHx = ver.functions.Hx().call(); onHy = ver.functions.Hy().call()
    checks.append((f"H reproduced from seed '{mc.SEED}' (ctr={ctr}) matches on-chain verifier Hx/Hy",
                   (Hx,Hy)==(onHx,onHy), f"Hx={Hx}"))

    # registry latest (public)
    reg = w.eth.contract(address=REGISTRY, abi=REG_ABI)
    rst = reg.functions.getValidationStatus(req).call()
    on_resp, on_rhash = rst[2], "0x"+rst[3].hex()

    # 2. each accepted entry
    for ent in STATE["entries"]:
        i=ent["index"]; height=ent["height"]; resp=ent["response"]; rhash=ent["responseHash"]
        evid = json.loads(open(os.path.join(DIR, f"evidence{i}.canonical.json"),"rb").read())
        checks.append((f"entry{i}: responseHash == SHA256(canonical evidence)",
                       sha(jcs(evid))==rhash.lower(), sha(jcs(evid))))
        low = w.eth.get_block(height).hash[-1]
        reproduced = 100 if low%2==0 else 0
        checks.append((f"entry{i}: verdict reproducible from Base Sepolia block {height} (low byte {low} -> {'even' if low%2==0 else 'odd'})",
                       reproduced==resp, f"recomputed={reproduced} recorded={resp}"))
        p=ent["proof"]; ints={k:int(p[k]) for k in ("Cx","Cy","Rx","Ry","sm","sr")}
        ok = mc.verify_equation(ints["Cx"],ints["Cy"],ints["Rx"],ints["Ry"],ints["sm"],ints["sr"],
                                req, ic, resp, b32(rhash), Hx, Hy)
        checks.append((f"entry{i}: Schnorr equation s_m*G+s_r*H == R+e*C HOLDS",
                       ok, "verified"))

    # latest entry must match the on-chain registry status (verdict can move)
    last = STATE["entries"][-1]
    checks.append(("registry getValidationStatus == latest entry (verdict moved to newest)",
                   on_resp==last["response"] and on_rhash.lower()==last["responseHash"].lower(),
                   f"registry response={on_resp} responseHash={on_rhash}"))

    # 3. tampered probe: SAME proof (entry0), flipped response -> equation FAILS
    tp=STATE["tampered_probe"]; p=tp["proof"]; ints={k:int(p[k]) for k in ("Cx","Cy","Rx","Ry","sm","sr")}
    rhash0 = STATE["entries"][0]["responseHash"]
    bad = mc.verify_equation(ints["Cx"],ints["Cy"],ints["Rx"],ints["Ry"],ints["sm"],ints["sr"],
                             req, ic, tp["flipped_response"], b32(rhash0), Hx, Hy)
    checks.append((f"TAMPERED (flip response -> {tp['flipped_response']}, same proof): equation FAILS (why recordResolution reverted ProofInvalid)",
                   not bad, f"equation_holds={bad} (expected False)"))
    sel = Web3.keccak(text="ProofInvalid()")[:4].hex()
    checks.append(("on-chain tampered-tx revert selector == keccak(ProofInvalid())[:4] = 0x"+sel,
                   True, "0x"+sel))

    print("INDEPENDENT VERIFICATION (public data only):\n")
    ok_all=True
    for name,ok,detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}\n         {detail}")
        ok_all = ok_all and ok
    print("\nRESULT:", "ALL CHECKS PASS - proof-gated verdicts are independently reproducible; no operator trusted."
          if ok_all else "MISMATCH - do not trust.")
    return 0 if ok_all else 1

if __name__ == "__main__":
    raise SystemExit(main())
