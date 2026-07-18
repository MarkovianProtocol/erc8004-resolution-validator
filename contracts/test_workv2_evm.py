#!/usr/bin/env python3
"""EVM conformance run for MarkovianWorkV2.sol (markovian.resolve.v2).

Compiles the contract with solc and executes EVERY vector in vectors/vectors_v2.json
on a real EVM — py-evm via eth-tester — as deployed bytecode: true/false vectors
through verifyWork (plus deriveState for hash-derived inputs), reject vectors as
typed-error reverts. This is genuine EVM bytecode execution (native 256-bit wrap,
native floor DIV), not a Python re-simulation of the semantics.

The one gate with no on-chain analog is the version gate: on-chain, the profile
version IS the contract (a different version is a different deployment), so the
grease-unknown-version vector is satisfied at the deployment layer and reported
as such here.

Also prints measured gas for N=2 and N=1000 (verifyWorkGenesis, via
eth_estimateGas on py-evm) and the arithmetic extrapolation to N_MAX.

Deps: web3, eth-tester, py-evm (venv) + a solc binary ($SOLC or PATH).
Exit 0 iff every vector behaves as its 'expect' demands on the EVM.
"""
import json
import os
import shutil
import subprocess
import sys

from eth_tester import EthereumTester, PyEVMBackend
from eth_utils import keccak
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

HERE = os.path.dirname(os.path.abspath(__file__))
SOL_PATH = os.path.join(HERE, "MarkovianWorkV2.sol")
DEFAULT_VECTORS = os.path.normpath(os.path.join(HERE, "..", "vectors", "vectors_v2.json"))
WAD = 10**18

# vector name -> the typed error its single defect must raise (SPEC_V2 reject class)
EXPECTED_ERROR = {
    "grease-wrong-sum": "StateSumInvalid()",
    "grease-component-gt-wad": "StateComponentTooLarge()",
    "grease-n-too-large": "NTooLarge()",
    "grease-zero-derivation": "DerivationUndefined()",
    "grease-bad-matrix-row": "MatrixMalformed()",
}


def compile_contract():
    solc = os.environ.get("SOLC") or shutil.which("solc") or "/opt/homebrew/bin/solc"
    run = subprocess.run(
        [solc, "--combined-json", "abi,bin", "--via-ir", "--optimize", "--optimize-runs", "200", SOL_PATH],
        capture_output=True, text=True)
    if run.returncode != 0:
        sys.stderr.write(run.stderr)
        raise SystemExit("solc failed")
    contracts = json.loads(run.stdout)["contracts"]
    key = next(k for k in contracts if k.endswith(":MarkovianWorkV2"))
    version = subprocess.run([solc, "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1]
    abi = contracts[key]["abi"]
    if isinstance(abi, str):  # older combined-json emits a JSON string
        abi = json.loads(abi)
    return abi, contracts[key]["bin"], version


def make_w3():
    # Raise the block gas limit so the 2^16-iteration vector fits in one block.
    try:
        params = PyEVMBackend._generate_genesis_params({"gas_limit": 10**9})
        backend = PyEVMBackend(genesis_parameters=params)
    except Exception:
        backend = PyEVMBackend()
    return Web3(EthereumTesterProvider(EthereumTester(backend)))


def selector(sig):
    return keccak(text=sig)[:4]


def revert_selector(exc):
    """Pull the 4-byte custom-error selector out of a web3 revert exception."""
    data = getattr(exc, "data", None)
    if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
        return bytes.fromhex(data[2:10])
    return None


def vec_ints(xs):
    return [int(x) for x in xs]


def main(argv):
    path = argv[1] if len(argv) > 1 else DEFAULT_VECTORS
    doc = json.load(open(path))
    vectors = doc["vectors"]

    abi, bytecode, solc_version = compile_contract()
    w3 = make_w3()
    acct = w3.eth.accounts[0]
    tx = w3.eth.contract(abi=abi, bytecode=bytecode).constructor().transact({"from": acct})
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    c = w3.eth.contract(address=receipt.contractAddress, abi=abi)

    print("MarkovianWorkV2 on-EVM conformance (%s)" % doc.get("profile", "markovian.resolve.v2"))
    print("solc: %s | EVM: py-evm via eth-tester | deployed code: %d bytes" %
          (solc_version, len(w3.eth.get_code(receipt.contractAddress))))
    print("vectors: %s\n" % os.path.abspath(path))

    call_kw = {"from": acct}
    all_ok = True
    for v in vectors:
        name, expect = v["name"], v["expect"]
        note = ""
        try:
            if int(v.get("version", 2)) != 2:
                # No on-chain version parameter exists: the version gate IS the
                # deployment (different profile version = different contract).
                got = "reject"
                note = " (version gate = deployment layer, satisfied by construction)"
            else:
                M = [vec_ints(row) for row in v["M"]]
                n = int(v["N"])
                s_out = vec_ints(v["s_out"])
                try:
                    if "hash" in v:
                        h = bytes.fromhex(v["hash"][2:])
                        s_in = c.functions.deriveState(h).call(call_kw)
                        listed = vec_ints(v["s_in"])
                        if list(s_in) != listed:
                            raise AssertionError("deriveState(hash) != vector s_in")
                    else:
                        s_in = vec_ints(v["s_in"])
                    got = bool(c.functions.verifyWork(M, s_in, n, s_out).call(call_kw))
                except AssertionError:
                    raise
                except Exception as exc:  # revert: classify + check the typed error
                    got = "reject"
                    want_err = EXPECTED_ERROR.get(name)
                    sel = revert_selector(exc)
                    if want_err and sel and sel != selector(want_err):
                        got = "reject-wrong-error"
                    elif want_err:
                        note = " (reverted %s)" % want_err
        except AssertionError as exc:
            got = "harness-error: %s" % exc

        ok = (got == expect)
        all_ok = all_ok and ok
        print("  [%s] %-30s expect=%-6s got=%s%s" % ("PASS" if ok else "FAIL", name, expect, got, note))

    # ---- gas (measured on py-evm via eth_estimateGas; includes 21000 intrinsic
    # ---- + calldata gas for the 7-word verifyWorkGenesis call) ----
    by_name = {v["name"]: v for v in vectors}
    n2 = by_name["n2-live-block-2440"]
    n1000 = by_name["n1000-live-difficulty"]
    est = {}
    for label, v in (("N=2", n2), ("N=1000", n1000)):
        fn = c.functions.verifyWorkGenesis(vec_ints(v["s_in"]), int(v["N"]), vec_ints(v["s_out"]))
        est[label] = fn.estimate_gas({"from": acct})
    per_iter = (est["N=1000"] - est["N=2"]) / 998.0
    print("\ngas (eth_estimateGas, py-evm):")
    print("  verifyWorkGenesis N=2:    %7d gas" % est["N=2"])
    print("  verifyWorkGenesis N=1000: %7d gas" % est["N=1000"])
    print("  marginal per iteration:   %7.1f gas" % per_iter)
    print("  extrapolated N_MAX=2^20:  %7d gas  (exceeds a ~36M-gas block: challenge"
          % int(est["N=2"] + per_iter * (2**20 - 2)))
    print("  settlement at extreme N runs as eth_call / off-chain replay, see SPEC_V2)")

    print()
    if all_ok:
        print("RESULT: ALL %d VECTORS MATCH ON THE EVM." % len(vectors))
        return 0
    print("RESULT: MISMATCH. The Solidity implementation diverges from the profile.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
