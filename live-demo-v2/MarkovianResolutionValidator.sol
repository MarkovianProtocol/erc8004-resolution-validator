// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IMarkovianVerifier} from "./IMarkovianVerifier.sol";

/// @notice Canonical ERC-8004 ValidationRegistry (v2.0.0), CREATE2 singleton.
interface IValidationRegistry {
    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external;

    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external;
}

/// @title  MarkovianResolutionValidator (v2, proof-enforcing)
/// @author Markovian Protocol
/// @notice An ERC-8004 validator with NO owner, NO admin, NO validator key. A verdict is
///         written only if an on-chain proof verifies against the exact verdict tuple.
///         Verdicts may move, but only by a new valid proof, never by authorship. Every
///         verdict is appended to a hash-linked history whose head is frozen to Bitcoin.
///
///         Bitcoin freezes the CLAIM (what/when). Ethereum moves the VERDICT (what it
///         means now). The rule is immutable; the state is free to move.
contract MarkovianResolutionValidator {
    string public constant METHOD_TAG = "markovian.resolve.v1";

    IValidationRegistry public immutable registry;
    IMarkovianVerifier  public immutable verifier;

    struct Request {
        uint256 agentId;
        bytes32 inputCommit; // inputs bound BEFORE any outcome (anti-backfill)
        bool exists;
    }

    struct Entry {
        uint8   response;      // 100 = TRUE/PASS, 0 = FALSE/FAIL
        bytes32 responseHash;  // Bitcoin-anchorable resolution root
        bytes32 inputCommit;
        bytes32 prevEntry;     // hash-link to prior entry (append-only chain)
        uint64  ts;
        bool    challenged;
        bool    failed;
    }

    mapping(bytes32 => Request)  public  requests;        // requestHash => request
    mapping(bytes32 => Entry[])  private _history;        // requestHash => append-only entries
    mapping(uint256 => bytes32)  public  head;           // agentId => hash-linked log head
    mapping(bytes32 => bytes32)  public  headAnchoredTo; // headHash => Bitcoin commit ref (first-write-wins)

    event RequestCommitted(uint256 indexed agentId, bytes32 indexed requestHash, bytes32 inputCommit, string requestURI);
    event ResolutionRecorded(uint256 indexed agentId, bytes32 indexed requestHash, bytes32 responseHash, uint8 response, bytes32 head, uint256 entryIndex, string proofURI);
    event HeadAnchored(uint256 indexed agentId, bytes32 indexed headHash, bytes32 bitcoinRef);
    event Challenged(bytes32 indexed requestHash, uint256 entryIndex);
    event ChallengeResolved(bytes32 indexed requestHash, uint256 entryIndex, bool upheld);

    error RequestExists();
    error UnknownRequest();
    error PreCommitMissing();
    error ProofInvalid();
    error NoSuchEntry();
    error NotChallenged();
    error FullProofInvalid();

    constructor(IValidationRegistry _registry, IMarkovianVerifier _verifier) {
        registry = _registry;
        verifier = _verifier;
    }

    /// @notice Open a request and bind the pre-committed inputs BEFORE any outcome exists.
    function commitRequest(
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash,
        bytes32 inputCommit
    ) external {
        if (requests[requestHash].exists) revert RequestExists();
        if (inputCommit == bytes32(0)) revert PreCommitMissing();
        requests[requestHash] = Request({agentId: agentId, inputCommit: inputCommit, exists: true});
        // ERC-8004 wiring: ValidationRegistry.validationRequest requires msg.sender to be the
        // agent owner (or approved), so THIS contract cannot open the request. The agent owner
        // (EOA) calls registry.validationRequest(address(this), agentId, requestURI, requestHash)
        // DIRECTLY, naming this contract as the validator. This contract then holds the exclusive
        // right to call validationResponse (see recordResolution). commitRequest only binds the
        // pre-commit inputs on our side; it never weakens the proof-gate or the append-only log.
        emit RequestCommitted(agentId, requestHash, inputCommit, requestURI);
    }

    /// @notice Record a verdict. Authorization IS the proof: no owner, no key.
    ///         A tampered verdict changes `context`, the proof no longer verifies, revert.
    function recordResolution(
        bytes32 requestHash,
        uint8 response,
        string calldata proofURI,
        bytes32 responseHash,
        bytes calldata proof
    ) external {
        Request memory r = requests[requestHash];
        if (!r.exists) revert UnknownRequest();
        if (!verifier.verify(requestHash, r.inputCommit, response, responseHash, proof)) revert ProofInvalid();

        bytes32 prev = head[r.agentId];
        _history[requestHash].push(Entry({
            response: response,
            responseHash: responseHash,
            inputCommit: r.inputCommit,
            prevEntry: prev,
            ts: uint64(block.timestamp),
            challenged: false,
            failed: false
        }));
        uint256 idx = _history[requestHash].length - 1;
        bytes32 entryHash = keccak256(abi.encode(requestHash, idx, response, responseHash, r.inputCommit, prev));
        head[r.agentId] = keccak256(abi.encodePacked(prev, entryHash));

        registry.validationResponse(requestHash, response, proofURI, responseHash, METHOD_TAG);
        emit ResolutionRecorded(r.agentId, requestHash, responseHash, response, head[r.agentId], idx, proofURI);
    }

    /// @notice Freeze the current append-only head to Bitcoin. First-write-wins (no overwrite).
    ///         Adds no trust: the ref is checked against Bitcoin off-chain.
    function anchorHead(uint256 agentId, bytes32 bitcoinRef) external {
        bytes32 h = head[agentId];
        if (headAnchoredTo[h] == bytes32(0)) {
            headAnchoredTo[h] = bitcoinRef;
            emit HeadAnchored(agentId, h, bitcoinRef);
        }
    }

    // ---- cost model (b): a challenge is settled by RECOMPUTATION, never a vote ----

    function challenge(bytes32 requestHash, uint256 entryIndex) external {
        if (entryIndex >= _history[requestHash].length) revert NoSuchEntry();
        _history[requestHash][entryIndex].challenged = true;
        emit Challenged(requestHash, entryIndex);
    }

    /// @notice Uphold a challenged entry by supplying the full computation proof.
    ///         Invalid proof reverts (no state change); it never lets a griefer mark failed.
    function resolveChallenge(bytes32 requestHash, uint256 entryIndex, bytes calldata snarkProof) external {
        if (entryIndex >= _history[requestHash].length) revert NoSuchEntry();
        Entry storage e = _history[requestHash][entryIndex];
        if (!e.challenged) revert NotChallenged();
        Request memory r = requests[requestHash];
        if (!verifier.verifyFull(requestHash, r.inputCommit, e.response, e.responseHash, snarkProof)) revert FullProofInvalid();
        e.challenged = false; // upheld by recomputation
        emit ChallengeResolved(requestHash, entryIndex, true);
    }

    // ---- views ----
    function historyLength(bytes32 requestHash) external view returns (uint256) {
        return _history[requestHash].length;
    }
    function getEntry(bytes32 requestHash, uint256 i) external view returns (Entry memory) {
        if (i >= _history[requestHash].length) revert NoSuchEntry();
        return _history[requestHash][i];
    }
    function latest(bytes32 requestHash) external view returns (Entry memory) {
        uint256 n = _history[requestHash].length;
        if (n == 0) revert NoSuchEntry();
        return _history[requestHash][n - 1];
    }
}
