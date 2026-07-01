// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @notice Minimal interface to the canonical ERC-8004 ValidationRegistry (v2.0.0),
///         deployed via CREATE2 at 0x8004Cb1BF31DAf7788923b405b754f57acEB4272 across
///         supported EVM chains.
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

/// @title  MarkovianResolutionValidator
/// @author Markovian Protocol
/// @notice An ERC-8004 validator that settles an agent's outcome-claim by
///         DETERMINISTIC REPLAY of a committed function over public data, with the
///         result anchored to Bitcoin via OpenTimestamps. It fills the
///         ValidationRegistry's explicitly-undefined validator-method slot — the
///         EIP names "stakers re-running the job, zkML verifiers, TEE oracles,
///         trusted judges" — with a fourth type: trustless replay.
///
/// @dev    THE TRUST MODEL IS THE POINT. A consumer does NOT trust this contract's
///         score, nor the resolver, nor a committee, nor a TEE. `responseURI` serves
///         a self-contained replayable proof bundle (spec id, committed model M,
///         committed public inputs, merkle root, and the Bitcoin `.ots` proof).
///         `responseHash` is that Bitcoin-anchored resolution root. Anyone reruns
///         the committed M over the committed inputs, rebuilds the root, checks it
///         equals `responseHash`, and confirms `responseHash` is timestamped in
///         Bitcoin. The referee is a pure function anyone can run — no oracle vote,
///         no stake, no enclave, no database, no trust in the resolver.
contract MarkovianResolutionValidator {
    /// @notice Method tag recorded on every response; agents list this in their
    ///         ERC-8004 registration `supportedTrust[]` to accept this validator.
    string public constant METHOD_TAG = "markovian.resolve.v1";

    IValidationRegistry public immutable registry;
    address public resolver; // off-chain resolver authorized to post verdicts

    /// @dev Mirror of the anchored resolution for indexers. The authoritative,
    ///      independently-verifiable proof lives off-chain at `proofURI`.
    event ResolutionRecorded(
        uint256 indexed agentId,
        bytes32 indexed claimCommit, // == requestHash: the agent's committed claim
        bytes32 merkleRoot,          // == responseHash: Bitcoin-anchored resolution root
        uint8 verdict,               // 100 = claim TRUE, 0 = claim FALSE
        string proofURI
    );

    error NotResolver();

    modifier onlyResolver() {
        if (msg.sender != resolver) revert NotResolver();
        _;
    }

    constructor(IValidationRegistry _registry, address _resolver) {
        registry = _registry;
        resolver = _resolver;
    }

    /// @notice Record a trustless resolution of an agent's claim into ERC-8004.
    /// @param agentId     agent (IdentityRegistry NFT id) whose claim is validated
    /// @param claimCommit Markovian claim/existence commitment (used as requestHash);
    ///                    committed BEFORE the outcome, so it cannot be backfilled
    /// @param merkleRoot  deterministic-replay resolution root (used as responseHash),
    ///                    independently anchored to Bitcoin via OpenTimestamps
    /// @param verdict     100 if the committed replay proves the claim TRUE, else 0
    /// @param proofURI    URL of the replayable proof bundle (spec, M, inputs, .ots)
    function recordResolution(
        uint256 agentId,
        bytes32 claimCommit,
        bytes32 merkleRoot,
        uint8 verdict,
        string calldata proofURI
    ) external onlyResolver {
        // 1) open the request naming this contract as the validator
        registry.validationRequest(address(this), agentId, proofURI, claimCommit);
        // 2) post the trustless verdict, the anchored root, and the replayable proof
        registry.validationResponse(claimCommit, verdict, proofURI, merkleRoot, METHOD_TAG);
        emit ResolutionRecorded(agentId, claimCommit, merkleRoot, verdict, proofURI);
    }

    function setResolver(address _resolver) external onlyResolver {
        resolver = _resolver;
    }
}
