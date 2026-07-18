// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title  MarkovianWorkV2 — the integer work function (markovian.resolve.v2)
/// @author Markovian Protocol
/// @notice On-chain implementation of SPEC_V2.md: s_N = M^N . s in WAD (1e18)
///         fixed-point unsigned integers, floor division, EXACT equality. No floats,
///         no tolerance — the two defects of the float64 v1 replay (tolerance
///         comparison, EVM-incompatibility) do not exist here.
///
///         Normative algorithm (SPEC_V2.md), reproduced by verifier/workfn_v2.py and
///         goverify/workv2.go on vectors/vectors_v2.json:
///
///           s'[i] = (M[i][0]*s[0])/WAD + (M[i][1]*s[1])/WAD + (M[i][2]*s[2])/WAD
///           s_N   = N plain iterations (N == 0 is the identity; no renormalization;
///                   exponentiation-by-squaring is NON-conformant: floor rounding is
///                   non-associative)
///
///         Malformed input reverts with a typed error (the spec's "reject" class);
///         a well-formed wrong claim returns false. The v2 version gate is this
///         contract itself: a different profile version is a different deployment.
///
///         This is a NEW, standalone contract: it does not modify the deployed
///         SchnorrPedersenVerifier or MarkovianResolutionValidator sources. It is
///         the recomputation path a future verifier deployment wires behind
///         IMarkovianVerifier.verifyFull (Impl B), replacing the IMPL_B_PENDING stub:
///         a challenge is settled by recomputation, and recomputation is exact.
contract MarkovianWorkV2 {
    uint256 public constant WAD = 1e18;

    /// @notice N bound: caps verification work. 2^20 plain iterations. Reject above.
    uint256 public constant N_MAX = 1 << 20;

    error MatrixMalformed();        // entry > WAD, or a row does not sum to exactly WAD
    error StateComponentTooLarge(); // a state component exceeds WAD
    error StateSumInvalid();        // s_in components do not sum to exactly WAD
    error NTooLarge();              // N > N_MAX
    error DerivationUndefined();    // first 24 hash bytes are all zero (a+b+c == 0)

    /// @notice GENESIS_M v2: the exact WAD integers of the two-decimal float64
    ///         genesis values (0.70 -> 700000000000000000; no rounding anywhere).
    ///         Every row sums to exactly WAD.
    function genesisM() public pure returns (uint256[3][3] memory m) {
        m[0] = [uint256(700000000000000000), 250000000000000000, 50000000000000000];
        m[1] = [uint256(100000000000000000), 750000000000000000, 150000000000000000];
        m[2] = [uint256(200000000000000000), 150000000000000000, 650000000000000000];
    }

    /// @notice Integerized input derivation from a 32-byte block hash: a,b,c are the
    ///         first three big-endian uint64; s[i] = x_i*WAD / (a+b+c) floored; the
    ///         0..2 WAD-unit remainder is added to index 0, so sum(s) == WAD exactly.
    function deriveState(bytes32 h) public pure returns (uint256[3] memory s) {
        uint256 w = uint256(h);
        uint256 a = w >> 192;
        uint256 b = (w >> 128) & type(uint64).max;
        uint256 c = (w >> 64) & type(uint64).max;
        uint256 total = a + b + c;
        if (total == 0) revert DerivationUndefined();
        unchecked {
            // x_i < 2^64 and WAD < 2^60, so x_i*WAD < 2^124: no overflow.
            s[0] = (a * WAD) / total;
            s[1] = (b * WAD) / total;
            s[2] = (c * WAD) / total;
            s[0] += WAD - (s[0] + s[1] + s[2]); // remainder rule: to index 0
        }
    }

    function _checkMatrix(uint256[3][3] memory m) private pure {
        for (uint256 i; i < 3; ++i) {
            uint256 rowSum;
            for (uint256 j; j < 3; ++j) {
                if (m[i][j] > WAD) revert MatrixMalformed();
                rowSum += m[i][j];
            }
            if (rowSum != WAD) revert MatrixMalformed();
        }
    }

    function _checkState(uint256[3] memory s, bool requireSum) private pure {
        if (s[0] > WAD || s[1] > WAD || s[2] > WAD) revert StateComponentTooLarge();
        if (requireSum && s[0] + s[1] + s[2] != WAD) revert StateSumInvalid();
    }

    /// @dev The plain iteration loop. Bounds make `unchecked` safe: every M entry and
    ///      every state component is <= WAD, so each product is <= WAD^2 = 1e36 < 2^120
    ///      and each new component is <= sum_j M[i][j]*max(s)/WAD = max(s) <= WAD
    ///      (rows sum to exactly WAD, enforced by _checkMatrix) — the max component
    ///      never grows, for any N.
    function _run(uint256[3][3] memory m, uint256[3] memory sIn, uint256 n)
        private
        pure
        returns (uint256[3] memory s)
    {
        uint256 m00 = m[0][0]; uint256 m01 = m[0][1]; uint256 m02 = m[0][2];
        uint256 m10 = m[1][0]; uint256 m11 = m[1][1]; uint256 m12 = m[1][2];
        uint256 m20 = m[2][0]; uint256 m21 = m[2][1]; uint256 m22 = m[2][2];
        uint256 s0 = sIn[0]; uint256 s1 = sIn[1]; uint256 s2 = sIn[2];
        unchecked {
            for (uint256 k; k < n; ++k) {
                // Per-element floor, then sum — native EVM division IS floor division.
                uint256 t0 = (m00 * s0) / WAD + (m01 * s1) / WAD + (m02 * s2) / WAD;
                uint256 t1 = (m10 * s0) / WAD + (m11 * s1) / WAD + (m12 * s2) / WAD;
                uint256 t2 = (m20 * s0) / WAD + (m21 * s1) / WAD + (m22 * s2) / WAD;
                s0 = t0; s1 = t1; s2 = t2;
            }
        }
        s[0] = s0; s[1] = s1; s[2] = s2;
    }

    /// @notice Compute s_N = M^N . sIn under the v2 profile. Reverts typed on
    ///         malformed input (gate order per SPEC_V2.md: N, matrix, s_in).
    function computeWork(uint256[3][3] memory m, uint256[3] memory sIn, uint256 n)
        public
        pure
        returns (uint256[3] memory)
    {
        if (n > N_MAX) revert NTooLarge();
        _checkMatrix(m);
        _checkState(sIn, true);
        return _run(m, sIn, n);
    }

    /// @notice The verdict: true iff the claimed output is EXACTLY the recomputed
    ///         s_N — equality of every WAD digit, no tolerance. Malformed input
    ///         (spec "reject" class) reverts typed and is never a false verdict.
    function verifyWork(
        uint256[3][3] memory m,
        uint256[3] memory sIn,
        uint256 n,
        uint256[3] memory sOutClaimed
    ) public pure returns (bool) {
        if (n > N_MAX) revert NTooLarge();
        _checkMatrix(m);
        _checkState(sIn, true);
        _checkState(sOutClaimed, false); // outputs need not sum to WAD (M is
        // row-stochastic acting on a column vector; the iteration does not
        // preserve the sum and never renormalizes), but no reachable component
        // exceeds WAD — a claim outside the domain is malformed, not false.
        uint256[3] memory got = _run(m, sIn, n);
        return got[0] == sOutClaimed[0] && got[1] == sOutClaimed[1] && got[2] == sOutClaimed[2];
    }

    /// @notice verifyWork against the committed genesis matrix.
    function verifyWorkGenesis(uint256[3] memory sIn, uint256 n, uint256[3] memory sOutClaimed)
        external
        pure
        returns (bool)
    {
        return verifyWork(genesisM(), sIn, n, sOutClaimed);
    }
}
