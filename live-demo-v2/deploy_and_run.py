#!/usr/bin/env python3
"""Deploy + drive the proof-enforcing Markovian ERC-8004 validator on Base Sepolia.
Runs the full acceptance test A-E. Testnet only. Prints every tx hash.

Flow (respecting the live ERC-8004 access rules):
  owner EOA -> registry.validationRequest(validator, 7816, uri, requestHash)   [owner-only]
  owner EOA -> validator.commitRequest(7816, uri, requestHash, inputCommit)    [our precommit]
  anyone    -> validator.recordResolution(...) which, iff the proof verifies,
               calls registry.validationResponse(...) as the NAMED validator.
"""
import os, sys, json, time, hashlib
from web3 import Web3
import solcx
import markov_crypto as mc

DIR = os.path.expanduser("~/markovian/erc8004-resolution-validator/live-demo-v2")
RPCS = ["https://base-sepolia-rpc.publicnode.com", "https://sepolia.base.org"]
CHAIN_ID = 84532
AGENT_ID = 7816
REGISTRY = Web3.to_checksum_address("0x8004Cb1BF31DAf7788923b405b754f57acEB4272")
IDENTITY = Web3.to_checksum_address("0x8004A818BFB912233c491871b3d84c89A494BD9e")
BASESCAN = "https://sepolia.basescan.org/tx/0x"

REG_ABI = [
 {"name":"validationRequest","type":"function","stateMutability":"nonpayable","inputs":[
   {"name":"validatorAddress","type":"address"},{"name":"agentId","type":"uint256"},
   {"name":"requestURI","type":"string"},{"name":"requestHash","type":"bytes32"}],"outputs":[]},
 {"name":"validationResponse","type":"function","stateMutability":"nonpayable","inputs":[
   {"name":"requestHash","type":"bytes32"},{"name":"response","type":"uint8"},
   {"name":"responseURI","type":"string"},{"name":"responseHash","type":"bytes32"},
   {"name":"tag","type":"string"}],"outputs":[]},
 {"name":"getValidationStatus","type":"function","stateMutability":"view",
   "inputs":[{"name":"requestHash","type":"bytes32"}],
   "outputs":[{"type":"address"},{"type":"uint256"},{"type":"uint8"},{"type":"bytes32"},{"type":"string"},{"type":"uint256"}]},
]
ID_ABI = [{"name":"ownerOf","type":"function","stateMutability":"view",
           "inputs":[{"name":"tokenId","type":"uint256"}],"outputs":[{"type":"address"}]}]

def call_retry(fn, tries=10, delay=3):
    """Retry a .call() that can transiently revert/error because a multi-node RPC read hit a lagging node."""
    last=None
    for i in range(tries):
        try: return fn.call()
        except Exception as ex:
            last=ex; time.sleep(delay)
    raise last

def jcs(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def sha256_b32(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def hx(b: bytes) -> str: return "0x" + b.hex()

def connect():
    for u in RPCS:
        w = Web3(Web3.HTTPProvider(u, request_kwargs={"timeout": 40}))
        if w.is_connected() and w.eth.chain_id == CHAIN_ID:
            print("RPC:", u); return w
    sys.exit("no RPC")

def load_eoa():
    kf = os.getenv("EOA_KEYFILE", os.path.expanduser("~/.secrets/mkv_testnet_eoa.json"))
    a = json.load(open(kf))
    return Web3.to_checksum_address(a["address"]), a["private_key"]

def compile_all():
    solcx.set_solc_version("0.8.26")
    srcs = {}
    for f in ["IMarkovianVerifier.sol","SchnorrPedersenVerifier.sol","MarkovianResolutionValidator.sol"]:
        srcs[f] = {"content": open(os.path.join(DIR, f)).read()}
    out = solcx.compile_standard({
        "language":"Solidity","sources":srcs,
        "settings":{"optimizer":{"enabled":True,"runs":200},
                    "outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}},
        allow_paths=DIR, base_path=DIR)
    def pick(fname, cname):
        c = out["contracts"][fname][cname]
        return c["abi"], c["evm"]["bytecode"]["object"]
    v_abi, v_bin = pick("SchnorrPedersenVerifier.sol","SchnorrPedersenVerifier")
    m_abi, m_bin = pick("MarkovianResolutionValidator.sol","MarkovianResolutionValidator")
    return v_abi, v_bin, m_abi, m_bin

class Tx:
    def __init__(self, w, acct, pk):
        self.w=w; self.acct=acct; self.pk=pk
        self.nonce = w.eth.get_transaction_count(acct, "pending")   # local nonce mgmt (multi-node RPC safe)
    def _gasprice(self):
        return max(int(self.w.eth.gas_price*2), 12_000_000)         # floor 0.012 gwei
    def _base(self, gas, gasprice=None):
        return {"from":self.acct,"nonce":self.nonce,"gas":gas,
                "gasPrice":gasprice or self._gasprice(),"chainId":CHAIN_ID}
    def send(self, fn, label, gas=None):
        if gas is None: gas = int(fn.estimate_gas({"from":self.acct})*1.3)
        r = self._fire(lambda gp: fn.build_transaction(self._base(gas, gp)), label)
        assert r.status==1, f"{label} FAILED status0"; return r
    def deploy(self, abi, bytecode, args, label):
        c = self.w.eth.contract(abi=abi, bytecode=bytecode); cons = c.constructor(*args)
        gas = int(cons.estimate_gas({"from":self.acct})*1.3)
        r = self._fire(lambda gp: cons.build_transaction(self._base(gas, gp)), label)
        assert r.status==1, f"{label} deploy FAILED"; return r
    def send_expect_revert(self, fn, label, gas=600000):
        r = self._fire(lambda gp: fn.build_transaction(self._base(gas, gp)), label)  # fixed gas, skip estimate
        assert r.status==0, f"{label} did NOT revert (status1)!"; return r
    def _fire(self, build, label):
        gp = self._gasprice()
        for attempt in range(5):
            tx = build(gp)
            s = self.w.eth.account.sign_transaction(tx, self.pk)
            try:
                h = self.w.eth.send_raw_transaction(s.raw_transaction)
            except Exception as ex:
                msg = str(ex).lower()
                if ("underpriced" in msg or "already known" in msg or "replacement" in msg) and attempt < 4:
                    gp = int(gp*1.4)+1; time.sleep(2); print(f"  [{label}] bump gasPrice -> {gp}"); continue
                raise
            hh = h.hex() if h.hex().startswith("0x") else "0x"+h.hex()
            print(f"  [{label}] sent {hh}  {BASESCAN}{hh[2:]}")
            r = self.w.eth.wait_for_transaction_receipt(h, timeout=240)
            print(f"  [{label}] status={r.status} gasUsed={r.gasUsed} block={r.blockNumber}")
            self.nonce += 1
            return r
        raise RuntimeError(f"{label}: exhausted retries")

def parity_verdict(w, block_num):
    """Public, reproducible claim: is the low byte of the Base Sepolia block hash EVEN? 100=PASS(even)/0=FAIL(odd)."""
    b = w.eth.get_block(block_num)
    low = b.hash[-1]                 # last byte of 32-byte block hash
    return (100 if low % 2 == 0 else 0), "0x"+b.hash.hex(), low

def main():
    w = connect(); acct, pk = load_eoa(); tx = Tx(w, acct, pk)
    ident = w.eth.contract(address=IDENTITY, abi=ID_ABI)
    owner = ident.functions.ownerOf(AGENT_ID).call()
    print(f"EOA={acct} bal={w.eth.get_balance(acct)/1e18:.8f} ETH")
    print(f"agentId {AGENT_ID} owner on-chain = {owner}  (owner==EOA: {owner.lower()==acct.lower()})")
    assert owner.lower()==acct.lower(), "EOA does not own agent 7816"

    Hx, Hy, ctr = mc.derive_H()
    print(f"H: seed='{mc.SEED}' ctr={ctr}\n   Hx={Hx}\n   Hy={Hy}")

    v_abi, v_bin, m_abi, m_bin = compile_all()
    print("compiled: verifier bin", len(v_bin)//2, "B; validator bin", len(m_bin)//2, "B")

    rep = {"network":"base-sepolia","chainId":CHAIN_ID,"agentId":AGENT_ID,
           "H":{"seed":mc.SEED,"ctr":ctr,"Hx":str(Hx),"Hy":str(Hy)},"tx":{}, "checks":{}}

    # ---- A: deploy both ----
    print("\n== A: DEPLOY ==")
    rv = tx.deploy(v_abi, v_bin, [Hx, Hy], "deploy-verifier")
    verifier_addr = rv.contractAddress; rep["tx"]["deploy_verifier"]=rv.transactionHash.hex()
    rep["verifier"]=verifier_addr; print("  verifier:", verifier_addr)
    rm = tx.deploy(m_abi, m_bin, [REGISTRY, verifier_addr], "deploy-validator")
    validator_addr = rm.contractAddress; rep["tx"]["deploy_validator"]=rm.transactionHash.hex()
    rep["validator"]=validator_addr; print("  validator:", validator_addr)
    verifier = w.eth.contract(address=verifier_addr, abi=v_abi)
    validator = w.eth.contract(address=validator_addr, abi=m_abi)
    registry  = w.eth.contract(address=REGISTRY, abi=REG_ABI)

    # ---- claim + precommit ----
    tip = w.eth.block_number
    anchor = tip - 600
    # deterministic selection (disclosed in claim): first block b in [anchor, anchor+64)
    # whose low-byte parity differs from b+1, so the two verdicts genuinely MOVE.
    B0 = None
    for b in range(anchor, anchor+64):
        v0,_,_ = parity_verdict(w, b); v1,_,_ = parity_verdict(w, b+1)
        if v0 != v1: B0 = b; break
    if B0 is None: B0 = anchor
    B1 = B0 + 1
    print(f"\nclaim blocks: B0={B0} B1={B1} (anchor tip-600={anchor})")

    claim = {"protocol":"markovian.resolve.v1","statement":
             "Verdict for entry k: is the low byte of the Base Sepolia block hash EVEN? PASS(100)=even, FAIL(0)=odd.",
             "resolution_function":{"chain":"base-sepolia","chainId":CHAIN_ID,
                 "rule":"verdict = 100 if (int(blockhash(height)) & 0xff) % 2 == 0 else 0",
                 "series":{"entry0_height":B0,"entry1_height":B1},
                 "selection":"B0 = first block in [tip_at_build-600, +64) whose low-byte parity differs from B0+1"},
             "agentId":AGENT_ID}
    claim_canon = jcs(claim)
    request_hash = sha256_b32(claim_canon)
    preinputs = {"agentId":AGENT_ID,"claimHash":hx(request_hash),
                 "inputs":{"chain":"base-sepolia","entry0_height":B0,"entry1_height":B1},
                 "bound":"before any outcome (anti-backfill)"}
    input_commit = sha256_b32(jcs(preinputs))
    open(os.path.join(DIR,"claim.canonical.json"),"wb").write(claim_canon)
    json.dump(claim, open(os.path.join(DIR,"claim.pretty.json"),"w"), indent=1)
    json.dump(preinputs, open(os.path.join(DIR,"preinputs.pretty.json"),"w"), indent=1)
    open(os.path.join(DIR,"preinputs.canonical.json"),"wb").write(jcs(preinputs))
    rep["requestHash"]=hx(request_hash); rep["inputCommit"]=hx(input_commit)
    rep["blocks"]={"B0":B0,"B1":B1}
    requestURI = "local://live-demo-v2/claim.pretty.json"
    print("requestHash =", hx(request_hash), "\ninputCommit =", hx(input_commit))

    # owner opens ERC-8004 request naming OUR validator; then our precommit
    print("\n== open ERC-8004 request (owner EOA) + precommit ==")
    r = tx.send(registry.functions.validationRequest(validator_addr, AGENT_ID, requestURI, request_hash), "validationRequest")
    rep["tx"]["validationRequest"]=r.transactionHash.hex()
    r = tx.send(validator.functions.commitRequest(AGENT_ID, requestURI, request_hash, input_commit), "commitRequest")
    rep["tx"]["commitRequest"]=r.transactionHash.hex()
    st = call_retry(registry.functions.getValidationStatus(request_hash))
    print("  registry status after request:", st[0], "validator==ours:", st[0].lower()==validator_addr.lower())

    # ---- B: valid proof -> recordResolution SUCCEEDS ----
    print("\n== B: VALID RECORD (entry 0) ==")
    resp0, rhash0_hex, low0 = parity_verdict(w, B0)
    evid0 = {"entry":0,"height":B0,"blockhash":rhash0_hex,"low_byte":low0,
             "verdict":resp0,"verdict_label":"PASS(even)" if resp0==100 else "FAIL(odd)"}
    rhash0 = sha256_b32(jcs(evid0))
    pr0 = mc.prove(request_hash, input_commit, resp0, rhash0, Hx, Hy)
    # eth_call the pure verifier BEFORE spending gas
    ok0 = call_retry(verifier.functions.verify(request_hash, input_commit, resp0, rhash0, pr0["proof"]))
    print(f"  entry0 verdict={resp0} responseHash={hx(rhash0)} on-chain verify()={ok0}")
    assert ok0, "verifier rejected a valid proof (byte-packing mismatch!)"
    json.dump(evid0, open(os.path.join(DIR,"evidence0.pretty.json"),"w"), indent=1)
    open(os.path.join(DIR,"evidence0.canonical.json"),"wb").write(jcs(evid0))
    responseURI0 = "local://live-demo-v2/evidence0.pretty.json"
    r = tx.send(validator.functions.recordResolution(request_hash, resp0, responseURI0, rhash0, pr0["proof"]), "record-entry0")
    rep["tx"]["record_entry0"]=r.transactionHash.hex()
    hist = call_retry(validator.functions.historyLength(request_hash))
    e0 = call_retry(validator.functions.getEntry(request_hash, 0))
    head_after0 = call_retry(validator.functions.head(AGENT_ID))
    rst = call_retry(registry.functions.getValidationStatus(request_hash))
    print(f"  historyLength={hist} entry0.response={e0[0]} entry0.prevEntry={hx(e0[3])}")
    print(f"  head[agent]={hx(head_after0)}")
    print(f"  registry getValidationStatus: response={rst[2]} tag={rst[4]} responseHash={hx(rst[3])}")
    rep["checks"]["B"]={"historyLength":hist,"entry0_response":e0[0],
        "registry_response":rst[2],"registry_responseHash":hx(rst[3]),"head_after0":hx(head_after0)}

    # ---- C: THE MONEY SHOT: same proof, flipped response -> REVERT ProofInvalid ----
    print("\n== C: TAMPERED (flip response, same proof) -> must REVERT ==")
    flipped = 0 if resp0==100 else 100
    # eth_call the verifier to show it returns false for the tampered tuple
    ok_bad = call_retry(verifier.functions.verify(request_hash, input_commit, flipped, rhash0, pr0["proof"]))
    print(f"  verifier.verify(flipped={flipped}, same proof) = {ok_bad}  (expected False)")
    assert not ok_bad, "verifier ACCEPTED a tampered tuple -- proof-gate broken!"
    # decode the on-chain revert reason via eth_call
    revert_reason = None
    try:
        validator.functions.recordResolution(request_hash, flipped, responseURI0, rhash0, pr0["proof"]).call({"from":acct})
    except Exception as ex:
        revert_reason = str(ex)
    print("  eth_call revert:", (revert_reason or "")[:160])
    # send it as a real tx so it lands on BaseScan as a reverted tx
    r = tx.send_expect_revert(validator.functions.recordResolution(request_hash, flipped, responseURI0, rhash0, pr0["proof"]), "tampered-revert")
    rep["tx"]["tampered_revert"]=r.transactionHash.hex()
    # confirm no phantom entry / registry unchanged
    hist_after = call_retry(validator.functions.historyLength(request_hash))
    rst_after = call_retry(registry.functions.getValidationStatus(request_hash))
    print(f"  after revert: historyLength={hist_after} (unchanged) registry.response={rst_after[2]} (still {resp0})")
    proofinvalid_selector = Web3.keccak(text="ProofInvalid()")[:4].hex()
    rep["checks"]["C"]={"verifier_verify_flipped":ok_bad,"tx_status":r.status,
        "historyLength_unchanged":hist_after==hist,"ProofInvalid_selector":"0x"+proofinvalid_selector,
        "revert_reason":(revert_reason or "")[:200]}

    # ---- D: second valid proof -> appends entry 1, prevEntry links, head advances ----
    print("\n== D: SECOND VALID RECORD (entry 1) -> append-only ==")
    resp1, rhash1_hex, low1 = parity_verdict(w, B1)
    evid1 = {"entry":1,"height":B1,"blockhash":rhash1_hex,"low_byte":low1,
             "verdict":resp1,"verdict_label":"PASS(even)" if resp1==100 else "FAIL(odd)"}
    rhash1 = sha256_b32(jcs(evid1))
    pr1 = mc.prove(request_hash, input_commit, resp1, rhash1, Hx, Hy)
    ok1 = call_retry(verifier.functions.verify(request_hash, input_commit, resp1, rhash1, pr1["proof"]))
    print(f"  entry1 verdict={resp1} responseHash={hx(rhash1)} verify()={ok1}")
    assert ok1
    json.dump(evid1, open(os.path.join(DIR,"evidence1.pretty.json"),"w"), indent=1)
    open(os.path.join(DIR,"evidence1.canonical.json"),"wb").write(jcs(evid1))
    responseURI1 = "local://live-demo-v2/evidence1.pretty.json"
    r = tx.send(validator.functions.recordResolution(request_hash, resp1, responseURI1, rhash1, pr1["proof"]), "record-entry1")
    rep["tx"]["record_entry1"]=r.transactionHash.hex()
    hist2 = call_retry(validator.functions.historyLength(request_hash))
    e1 = call_retry(validator.functions.getEntry(request_hash, 1))
    head_after1 = call_retry(validator.functions.head(AGENT_ID))
    rst2 = call_retry(registry.functions.getValidationStatus(request_hash))
    links = hx(e1[3]) == hx(head_after0)          # entry1.prevEntry == head after entry0
    advanced = head_after1 != head_after0
    print(f"  historyLength={hist2} entry1.response={e1[0]} entry1.prevEntry={hx(e1[3])}")
    print(f"  prevEntry links to head-after-entry0: {links}")
    print(f"  head advanced: {advanced}  head[agent]={hx(head_after1)}")
    print(f"  registry now: response={rst2[2]} responseHash={hx(rst2[3])} (verdict moved: {rst2[2]!=resp0})")
    rep["checks"]["D"]={"historyLength":hist2,"entry1_response":e1[0],
        "entry1_prevEntry":hx(e1[3]),"head_after0":hx(head_after0),"head_after1":hx(head_after1),
        "prevEntry_links":links,"head_advanced":advanced,"verdict_moved":rst2[2]!=resp0}

    # persist proofs (public witnesses) + verdicts for verify.py
    rep["entries"]=[
        {"index":0,"height":B0,"response":resp0,"responseHash":hx(rhash0),
         "proof":{k:str(pr0[k]) for k in ["Cx","Cy","Rx","Ry","sm","sr","e"]},"responseURI":responseURI0},
        {"index":1,"height":B1,"response":resp1,"responseHash":hx(rhash1),
         "proof":{k:str(pr1[k]) for k in ["Cx","Cy","Rx","Ry","sm","sr","e"]},"responseURI":responseURI1},
    ]
    rep["tampered_probe"]={"flipped_response":flipped,"responseHash":hx(rhash0),
        "proof":{k:str(pr0[k]) for k in ["Cx","Cy","Rx","Ry","sm","sr"]}}
    json.dump(rep, open(os.path.join(DIR,"onchain_state.json"),"w"), indent=1)
    print("\nSTATE written -> onchain_state.json")
    print("\n==== TX SUMMARY ====")
    for k,v in rep["tx"].items():
        hh = v if v.startswith("0x") else "0x"+v
        print(f"  {k:20s} {BASESCAN}{hh[2:]}")

if __name__ == "__main__":
    main()
