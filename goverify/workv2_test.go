// Conformance test for the v2 integer work function: reproduce every vector in
// vectors/vectors_v2.json. Python (verifier/workfn_v2.py) generates/verifies the
// same file byte-exactly; both implementations passing it IS the cross-language
// agreement proof — every s_out digit, not just the classification.
package main

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func loadV2(t *testing.T) documentV2 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "vectors", "vectors_v2.json"))
	if err != nil {
		t.Fatalf("cannot read vectors_v2.json: %v", err)
	}
	var doc documentV2
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("cannot parse vectors_v2.json: %v", err)
	}
	if doc.Profile != "markovian.resolve.v2" {
		t.Fatalf("unexpected profile %q", doc.Profile)
	}
	return doc
}

func TestVectorsV2(t *testing.T) {
	doc := loadV2(t)
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range doc.Vectors {
		got, err := evaluateV2(v)
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if want := expectToken(v.Expect); got != want {
			t.Errorf("%s: expect=%s got=%s", v.Name, want, got)
		}
	}
}

func genesisMV2ForTest() [3][3]*big.Int {
	rows := [3][3]string{
		{"700000000000000000", "250000000000000000", "50000000000000000"},
		{"100000000000000000", "750000000000000000", "150000000000000000"},
		{"200000000000000000", "150000000000000000", "650000000000000000"},
	}
	var m [3][3]*big.Int
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			m[i][j] = mustInt(rows[i][j])
		}
	}
	return m
}

// TestNMaxBoundaryV2 pins the N bound from both sides: exactly N_MAX = 2^20
// iterations run; N_MAX+1 rejects before any iteration.
func TestNMaxBoundaryV2(t *testing.T) {
	m := genesisMV2ForTest()
	third := new(big.Int).Div(wad, big.NewInt(3))
	s0 := new(big.Int).Add(third, big.NewInt(1)) // remainder rule: +1 to index 0
	s := [3]*big.Int{s0, new(big.Int).Set(third), new(big.Int).Set(third)}

	out, err := workV2(m, s, nMaxV2)
	if err != nil {
		t.Fatalf("N == N_MAX must be accepted: %v", err)
	}
	for i := 0; i < 3; i++ {
		if out[i].Sign() < 0 || out[i].Cmp(wad) > 0 {
			t.Fatalf("component %d out of [0, WAD] after N_MAX iterations", i)
		}
	}
	if _, err := workV2(m, s, nMaxV2+1); err != errRejectV2 {
		t.Fatalf("N == N_MAX+1 must reject, got %v", err)
	}
}
