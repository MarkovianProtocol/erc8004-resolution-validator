// Command goverify is a standalone conformance verifier for Markovian RESOLVE
// (markovian.resolve.v1). It is a second, independent implementation of the same
// check the Python verifier and the on-chain SchnorrPedersenVerifier perform, and
// it MUST agree with them on every vector in vectors/vectors.json.
//
// Pure crypto. No chain RPC, no operator, no network, no third-party curve library.
// G1 arithmetic is implemented directly over math/big on alt_bn128 (BN254), the exact
// curve of the EVM ecAdd/ecMul precompiles: field modulus p below, y^2 = x^3 + 3,
// generator (1,2), scalar order n taken from each vector. keccak256 is the legacy
// Keccak in x/crypto/sha3. For each vector it recomputes the Fiat-Shamir challenge
// and checks the Pedersen+Schnorr binding equation on G1:
//
//	s_m*G + s_r*H == R + e*C
//	context = keccak256( requestHash[32] || inputCommit[32] || response[uint8] || responseHash[32] )
//	e       = uint256( keccak256( Rx[32] || Ry[32] || Cx[32] || Cy[32] || context[32] ) ) mod n
//
// Forward-compatibility gate, checked BEFORE any curve math:
//
//	unknown proof version   -> reject
//	response not in {0,100} -> reject
//
// Exit 0 iff every vector matches its "expect"; non-zero on any mismatch.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/sha3"
)

const supportedVersion = 1

// alt_bn128 (BN254) field modulus — the base field of the EVM G1 precompiles.
var fieldP, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

// curve: y^2 = x^3 + 3
var curveB = big.NewInt(3)

// g1 is an affine point on alt_bn128 G1; inf marks the point at infinity.
type g1 struct {
	x, y *big.Int
	inf  bool
}

func onCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(fieldP) >= 0 || y.Cmp(fieldP) >= 0 {
		return false
	}
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, fieldP)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, curveB)
	rhs.Mod(rhs, fieldP)
	return y2.Cmp(rhs) == 0
}

func newPoint(x, y *big.Int) (*g1, error) {
	if !onCurve(x, y) {
		return nil, fmt.Errorf("point (%s,%s) not on curve", x, y)
	}
	return &g1{x: new(big.Int).Set(x), y: new(big.Int).Set(y)}, nil
}

func doubleG1(a *g1) *g1 {
	if a.inf || a.y.Sign() == 0 {
		return &g1{inf: true}
	}
	p := fieldP
	num := new(big.Int).Mul(a.x, a.x)
	num.Mul(num, big.NewInt(3))     // 3x^2
	den := new(big.Int).Lsh(a.y, 1) // 2y
	den.Mod(den, p)
	lam := new(big.Int).Mul(num, new(big.Int).ModInverse(den, p))
	lam.Mod(lam, p)
	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, new(big.Int).Lsh(a.x, 1))
	x3.Mod(x3, p)
	y3 := new(big.Int).Sub(a.x, x3)
	y3.Mul(y3, lam)
	y3.Sub(y3, a.y)
	y3.Mod(y3, p)
	return &g1{x: x3, y: y3}
}

func addG1(a, b *g1) *g1 {
	if a.inf {
		return b
	}
	if b.inf {
		return a
	}
	p := fieldP
	if a.x.Cmp(b.x) == 0 {
		ySum := new(big.Int).Add(a.y, b.y)
		ySum.Mod(ySum, p)
		if ySum.Sign() == 0 {
			return &g1{inf: true} // a == -b
		}
		return doubleG1(a) // a == b
	}
	num := new(big.Int).Sub(b.y, a.y)
	den := new(big.Int).Sub(b.x, a.x)
	den.Mod(den, p)
	lam := new(big.Int).Mul(num, new(big.Int).ModInverse(den, p))
	lam.Mod(lam, p)
	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, a.x)
	x3.Sub(x3, b.x)
	x3.Mod(x3, p)
	y3 := new(big.Int).Sub(a.x, x3)
	y3.Mul(y3, lam)
	y3.Sub(y3, a.y)
	y3.Mod(y3, p)
	return &g1{x: x3, y: y3}
}

func scalarMulG1(k *big.Int, pt *g1) *g1 {
	res := &g1{inf: true}
	addend := pt
	kk := new(big.Int).Set(k)
	for kk.Sign() > 0 {
		if kk.Bit(0) == 1 {
			res = addG1(res, addend)
		}
		addend = doubleG1(addend)
		kk.Rsh(kk, 1)
	}
	return res
}

func equalG1(a, b *g1) bool {
	if a.inf || b.inf {
		return a.inf && b.inf
	}
	return a.x.Cmp(b.x) == 0 && a.y.Cmp(b.y) == 0
}

type proof struct {
	Cx string `json:"Cx"`
	Cy string `json:"Cy"`
	Rx string `json:"Rx"`
	Ry string `json:"Ry"`
	Sm string `json:"sm"`
	Sr string `json:"sr"`
}

type vector struct {
	Name         string      `json:"name"`
	Version      int         `json:"version"`
	G            []int64     `json:"G"`
	Hx           string      `json:"Hx"`
	Hy           string      `json:"Hy"`
	N            string      `json:"n"`
	RequestHash  string      `json:"requestHash"`
	InputCommit  string      `json:"inputCommit"`
	Response     int         `json:"response"`
	ResponseHash string      `json:"responseHash"`
	Proof        proof       `json:"proof"`
	Expect       interface{} `json:"expect"`
	Note         string      `json:"note"`
}

type document struct {
	Profile string   `json:"profile"`
	Vectors []vector `json:"vectors"`
}

func mustInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad integer: " + s)
	}
	return n
}

// b32 decodes a 0x-prefixed 32-byte hex string.
func b32(hexstr string) []byte {
	raw, err := hex.DecodeString(strings.TrimPrefix(hexstr, "0x"))
	if err != nil {
		panic(err)
	}
	if len(raw) != 32 {
		panic(fmt.Sprintf("expected 32 bytes, got %d", len(raw)))
	}
	return raw
}

func keccak(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// be32 returns the 32-byte big-endian encoding of x (x must be < 2^256).
func be32(x *big.Int) []byte {
	buf := make([]byte, 32)
	x.FillBytes(buf)
	return buf
}

// equationHolds recomputes the exact on-chain check for one vector.
func equationHolds(v vector) (bool, error) {
	n := mustInt(v.N)
	Gx := big.NewInt(v.G[0])
	Gy := big.NewInt(v.G[1])
	Hx, Hy := mustInt(v.Hx), mustInt(v.Hy)
	Cx, Cy := mustInt(v.Proof.Cx), mustInt(v.Proof.Cy)
	Rx, Ry := mustInt(v.Proof.Rx), mustInt(v.Proof.Ry)
	sm := new(big.Int).Mod(mustInt(v.Proof.Sm), n)
	sr := new(big.Int).Mod(mustInt(v.Proof.Sr), n)

	response := byte(v.Response)
	context := keccak(b32(v.RequestHash), b32(v.InputCommit), []byte{response}, b32(v.ResponseHash))
	eBytes := keccak(be32(Rx), be32(Ry), be32(Cx), be32(Cy), context)
	e := new(big.Int).Mod(new(big.Int).SetBytes(eBytes), n)

	G, err := newPoint(Gx, Gy)
	if err != nil {
		return false, err
	}
	H, err := newPoint(Hx, Hy)
	if err != nil {
		return false, err
	}
	C, err := newPoint(Cx, Cy)
	if err != nil {
		return false, err
	}
	R, err := newPoint(Rx, Ry)
	if err != nil {
		return false, err
	}

	lhs := addG1(scalarMulG1(sm, G), scalarMulG1(sr, H))
	rhs := addG1(R, scalarMulG1(e, C))
	return equalG1(lhs, rhs), nil
}

// evaluate returns the verifier classification token: "true", "false", or "reject".
func evaluate(v vector) (string, error) {
	version := v.Version
	if version == 0 {
		version = supportedVersion
	}
	if version != supportedVersion {
		return "reject", nil
	}
	if v.Response != 0 && v.Response != 100 {
		return "reject", nil
	}
	ok, err := equationHolds(v)
	if err != nil {
		return "", err
	}
	if ok {
		return "true", nil
	}
	return "false", nil
}

func expectToken(expect interface{}) string {
	switch e := expect.(type) {
	case bool:
		if e {
			return "true"
		}
		return "false"
	case string:
		return e
	default:
		return fmt.Sprintf("%v", e)
	}
}

func main() {
	path := filepath.Join("..", "vectors", "vectors.json")
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read vectors:", err)
		os.Exit(2)
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintln(os.Stderr, "cannot parse vectors:", err)
		os.Exit(2)
	}

	abs, _ := filepath.Abs(path)
	fmt.Printf("Markovian RESOLVE conformance (%s)\n", doc.Profile)
	fmt.Printf("vectors: %s\n\n", abs)

	allOK := true
	for _, v := range doc.Vectors {
		got, err := evaluate(v)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error on", v.Name, ":", err)
			os.Exit(2)
		}
		want := expectToken(v.Expect)
		ok := got == want
		allOK = allOK && ok
		status := "PASS"
		if !ok {
			status = "FAIL"
		}
		fmt.Printf("  [%s] %-26s expect=%-6s got=%s\n", status, v.Name, want, got)
	}

	fmt.Println()
	if allOK {
		fmt.Printf("RESULT: ALL %d VECTORS MATCH.\n", len(doc.Vectors))
		return
	}
	fmt.Println("RESULT: MISMATCH. A conformant verifier must reproduce every 'expect'.")
	os.Exit(1)
}
