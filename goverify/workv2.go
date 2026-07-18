// workv2.go implements the Markovian integer work function (markovian.resolve.v2):
// every quantity is a WAD (1e18) fixed-point unsigned integer, division is floor
// division, and the verdict is exact equality — no floats, no tolerance. It is a
// second, independent implementation of verifier/workfn_v2.py and MUST agree with
// it byte-exactly on every vector in vectors/vectors_v2.json (run `go test`).
//
// Arithmetic is math/big throughout: intermediate products reach WAD*WAD = 1e36
// (~2^120), past uint64. The normative algorithm (SPEC_V2.md):
//
//	s'[i] = (M[i][0]*s[0])/WAD + (M[i][1]*s[1])/WAD + (M[i][2]*s[2])/WAD   (floor each term)
//	s_N   = N plain iterations; no renormalization; N == 0 is the identity
//
// Input derivation: a,b,c = first 24 hash bytes as 3 big-endian uint64;
// s[i] = x_i*WAD / (a+b+c) floored; the remainder (0..2) is added to index 0 so the
// components sum to exactly WAD; a+b+c == 0 rejects.
//
// Forward-compatibility gate, checked BEFORE any arithmetic:
//
//	unknown version                          -> reject
//	N outside [0, 2^20]                      -> reject
//	M entry > WAD or row sum != WAD          -> reject
//	s component > WAD, or s_in sum != WAD    -> reject
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const supportedVersionV2 = 2
const nMaxV2 = 1 << 20

var wad = mustInt("1000000000000000000")

// errRejectV2 classifies malformed input under the v2 profile: reject cleanly,
// never crash, never silently coerce into a true/false verdict.
var errRejectV2 = errors.New("reject")

type vectorV2 struct {
	Name    string      `json:"name"`
	Version int         `json:"version"`
	M       [][]string  `json:"M"`
	Hash    string      `json:"hash"`
	SIn     []string    `json:"s_in"`
	N       int64       `json:"N"`
	SOut    []string    `json:"s_out"`
	Expect  interface{} `json:"expect"`
	Note    string      `json:"note"`
}

type documentV2 struct {
	Profile string     `json:"profile"`
	Vectors []vectorV2 `json:"vectors"`
}

func checkMatrixV2(m [3][3]*big.Int) error {
	for i := 0; i < 3; i++ {
		rowSum := new(big.Int)
		for j := 0; j < 3; j++ {
			if m[i][j].Sign() < 0 || m[i][j].Cmp(wad) > 0 {
				return errRejectV2
			}
			rowSum.Add(rowSum, m[i][j])
		}
		if rowSum.Cmp(wad) != 0 {
			return errRejectV2
		}
	}
	return nil
}

func checkStateV2(s [3]*big.Int, requireSum bool) error {
	sum := new(big.Int)
	for i := 0; i < 3; i++ {
		if s[i].Sign() < 0 || s[i].Cmp(wad) > 0 {
			return errRejectV2
		}
		sum.Add(sum, s[i])
	}
	if requireSum && sum.Cmp(wad) != 0 {
		return errRejectV2
	}
	return nil
}

// deriveSV2 is the integerized input derivation from a 32-byte block hash.
func deriveSV2(raw []byte) ([3]*big.Int, error) {
	var s [3]*big.Int
	if len(raw) != 32 {
		return s, errRejectV2
	}
	total := new(big.Int)
	var parts [3]*big.Int
	for i := 0; i < 3; i++ {
		parts[i] = new(big.Int).SetBytes(raw[8*i : 8*i+8])
		total.Add(total, parts[i])
	}
	if total.Sign() == 0 {
		return s, errRejectV2 // derivation undefined (v1 divides by zero here)
	}
	floorSum := new(big.Int)
	for i := 0; i < 3; i++ {
		s[i] = new(big.Int).Mul(parts[i], wad)
		s[i].Div(s[i], total)
		floorSum.Add(floorSum, s[i])
	}
	// Remainder rule: the 0..2 leftover WAD-units go to index 0; sum becomes exact.
	s[0].Add(s[0], new(big.Int).Sub(wad, floorSum))
	return s, nil
}

// stepV2 is one iteration: per-element floor((M[i][j]*s[j])/WAD), then sum.
func stepV2(m [3][3]*big.Int, s [3]*big.Int) [3]*big.Int {
	var out [3]*big.Int
	for i := 0; i < 3; i++ {
		acc := new(big.Int)
		for j := 0; j < 3; j++ {
			t := new(big.Int).Mul(m[i][j], s[j])
			t.Div(t, wad) // floor: all operands non-negative
			acc.Add(acc, t)
		}
		out[i] = acc
	}
	return out
}

// workV2 computes s_N = M^N . s by plain loop. Exponentiation-by-squaring is
// non-conformant: floor rounding makes the matmul non-associative.
func workV2(m [3][3]*big.Int, s [3]*big.Int, n int64) ([3]*big.Int, error) {
	var out [3]*big.Int
	if n < 0 || n > nMaxV2 {
		return out, errRejectV2
	}
	if err := checkMatrixV2(m); err != nil {
		return out, err
	}
	if err := checkStateV2(s, true); err != nil {
		return out, err
	}
	out = [3]*big.Int{new(big.Int).Set(s[0]), new(big.Int).Set(s[1]), new(big.Int).Set(s[2])}
	for k := int64(0); k < n; k++ {
		out = stepV2(m, out)
	}
	return out, nil
}

func parseVec3(ss []string) ([3]*big.Int, error) {
	var s [3]*big.Int
	if len(ss) != 3 {
		return s, errRejectV2
	}
	for i := 0; i < 3; i++ {
		s[i] = mustInt(ss[i])
	}
	return s, nil
}

// evaluateV2 returns the classification token for one vector: "true", "false",
// or "reject". Gate order is normative: version, N, matrix, derivation, s_in,
// s_out_claimed, then the math.
func evaluateV2(v vectorV2) (string, error) {
	version := v.Version
	if version == 0 {
		version = supportedVersionV2
	}
	if version != supportedVersionV2 {
		return "reject", nil
	}
	if v.N < 0 || v.N > nMaxV2 {
		return "reject", nil
	}
	if len(v.M) != 3 || len(v.M[0]) != 3 || len(v.M[1]) != 3 || len(v.M[2]) != 3 {
		return "reject", nil
	}
	var m [3][3]*big.Int
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			m[i][j] = mustInt(v.M[i][j])
		}
	}
	if err := checkMatrixV2(m); err != nil {
		return "reject", nil
	}

	var sIn [3]*big.Int
	if v.Hash != "" {
		raw, err := hex.DecodeString(strings.TrimPrefix(v.Hash, "0x"))
		if err != nil {
			return "", err
		}
		sIn, err = deriveSV2(raw)
		if err != nil {
			return "reject", nil
		}
		if len(v.SIn) == 3 {
			listed, err := parseVec3(v.SIn)
			if err != nil {
				return "", err
			}
			for i := 0; i < 3; i++ {
				// The vector's listed s_in disagreeing with the normative
				// derivation is a broken vector file, not a verdict.
				if listed[i].Cmp(sIn[i]) != 0 {
					return "", fmt.Errorf("%s: vector s_in != deriveSV2(hash)", v.Name)
				}
			}
		}
	} else {
		var err error
		sIn, err = parseVec3(v.SIn)
		if err != nil {
			return "reject", nil
		}
	}
	if err := checkStateV2(sIn, true); err != nil {
		return "reject", nil
	}

	sOut, err := parseVec3(v.SOut)
	if err != nil {
		return "reject", nil
	}
	if err := checkStateV2(sOut, false); err != nil {
		return "reject", nil
	}

	got, err := workV2(m, sIn, v.N)
	if err != nil {
		return "reject", nil
	}
	for i := 0; i < 3; i++ {
		if got[i].Cmp(sOut[i]) != 0 {
			return "false", nil
		}
	}
	return "true", nil
}
