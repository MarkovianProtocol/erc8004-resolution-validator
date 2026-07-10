// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IMarkovianVerifier
/// @notice On-chain proof checker for the Markovian validator. The validator writes
///         a verdict ONLY if `verify` returns true, so authorization is the proof,
///         not a validator key. `verifyFull` is the challenge-path (Impl B) SNARK.
interface IMarkovianVerifier {
    /// @notice Cheap binding check (Impl A): a Pedersen+Schnorr opening bound to this
    ///         exact verdict tuple. Runs on every write.
    /// @param  proof abi.encode(Cx, Cy, Rx, Ry, s_m, s_r) over BN128 G1.
    function verify(
        bytes32 requestHash,
        bytes32 inputCommit,
        uint8 response,
        bytes32 responseHash,
        bytes calldata proof
    ) external view returns (bool ok);

    /// @notice Full computation proof (Impl B): proves s_out = M*T^N*s_in. Only needed
    ///         to settle a challenge. Returns true iff the committed computation checks.
    function verifyFull(
        bytes32 requestHash,
        bytes32 inputCommit,
        uint8 response,
        bytes32 responseHash,
        bytes calldata snarkProof
    ) external view returns (bool ok);
}
