// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IMarkovianVerifier} from "./IMarkovianVerifier.sol";

/// @dev Minimal BN128 (alt_bn128) G1 ops via the EVM precompiles.
library BN128 {
    struct G1 { uint256 x; uint256 y; }

    /// ecAdd precompile at 0x06
    function add(G1 memory a, G1 memory b) internal view returns (G1 memory r) {
        uint256[4] memory input;
        input[0] = a.x; input[1] = a.y; input[2] = b.x; input[3] = b.y;
        bool ok;
        assembly { ok := staticcall(gas(), 0x06, input, 0x80, r, 0x40) }
        require(ok, "ecAdd");
    }

    /// ecMul precompile at 0x07
    function mul(G1 memory a, uint256 s) internal view returns (G1 memory r) {
        uint256[3] memory input;
        input[0] = a.x; input[1] = a.y; input[2] = s;
        bool ok;
        assembly { ok := staticcall(gas(), 0x07, input, 0x60, r, 0x40) }
        require(ok, "ecMul");
    }
}

/// @title SchnorrPedersenVerifier
/// @notice Impl A: verifies a Pedersen commitment opening via Schnorr, bound (through the
///         Fiat-Shamir challenge) to the exact (requestHash, inputCommit, response,
///         responseHash) being written. A proof for one verdict cannot be replayed onto
///         another, and no proof means no write. G = (1,2); H is a nothing-up-my-sleeve
///         second generator fixed at deployment (prover uses the same H).
///
///         Check: s_m*G + s_r*H == R + e*C, where e = keccak(R, C, context) mod n,
///         context = keccak(requestHash, inputCommit, response, responseHash).
contract SchnorrPedersenVerifier is IMarkovianVerifier {
    using BN128 for BN128.G1;

    // BN128 scalar field order
    uint256 internal constant N =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 public immutable Hx;
    uint256 public immutable Hy;

    constructor(uint256 _Hx, uint256 _Hy) {
        Hx = _Hx;
        Hy = _Hy;
    }

    function verify(
        bytes32 requestHash,
        bytes32 inputCommit,
        uint8 response,
        bytes32 responseHash,
        bytes calldata proof
    ) external view returns (bool) {
        (uint256 Cx, uint256 Cy, uint256 Rx, uint256 Ry, uint256 sm, uint256 sr) =
            abi.decode(proof, (uint256, uint256, uint256, uint256, uint256, uint256));

        bytes32 context = keccak256(abi.encodePacked(requestHash, inputCommit, response, responseHash));
        uint256 e = uint256(keccak256(abi.encodePacked(Rx, Ry, Cx, Cy, context))) % N;

        BN128.G1 memory G = BN128.G1(1, 2);
        BN128.G1 memory H = BN128.G1(Hx, Hy);
        BN128.G1 memory C = BN128.G1(Cx, Cy);
        BN128.G1 memory R = BN128.G1(Rx, Ry);

        BN128.G1 memory lhs = BN128.add(BN128.mul(G, sm), BN128.mul(H, sr));
        BN128.G1 memory rhs = BN128.add(R, BN128.mul(C, e));
        return lhs.x == rhs.x && lhs.y == rhs.y;
    }

    /// @notice Challenge-path SNARK over s_out = M*T^N*s_in. Not yet wired; a challenge
    ///         cannot be settled on-chain until this lands. Reverts rather than pretend.
    function verifyFull(bytes32, bytes32, uint8, bytes32, bytes calldata)
        external
        pure
        returns (bool)
    {
        revert("IMPL_B_PENDING");
    }
}
