package ecdh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	fecdh "github.com/julinox/funtls/tlssl/crypto/ecdh"
	"github.com/julinox/funtls/tlssl/names"
)

var allSG = []uint16{names.X25519, names.X448,
	names.SECP256R1, names.SECP384R1, names.SECP521R1}

var nonSupportedSG = map[uint16]bool{
	names.X25519: true,
	names.X448:   true,
}

func TestCurveame_NoSupportedCurves(t *testing.T) {
	//func pepito(t *testing.T) {

	res, err := fecdh.NewEcdhe(allSG)
	if err != nil {
		t.Fatalf("expected error, got nil")
	}

	if nonSupportedSG[res.Group] {
		t.Fatalf("returned non supported group '%v'", res.Group)
	}

	fmt.Println("Curva NonSupp: ", res.Curva.Params().Name)
}

func TestCurveame_IsOnCurve(t *testing.T) {

	res, err := fecdh.NewEcdhe(allSG)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res == nil {
		t.Fatalf("expected result, got nil")
	}

	if res.Priv == nil {
		t.Fatalf("priv key is nil")
	}

	if res.X == nil || res.Y == nil {
		t.Fatalf("public point is nil")
	}

	if !res.Curva.IsOnCurve(res.X, res.Y) {
		t.Fatalf("generated point is not on curve")
	}

	fmt.Println("CURVA-ISON: ", res.Curva.Params().Name)
}

func TestCurveame_PrivateMatchesPublic(t *testing.T) {

	res, err := fecdh.NewEcdhe(allSG)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	X2, Y2 := res.Curva.ScalarBaseMult(res.Priv)
	if X2.Cmp(res.X) != 0 || Y2.Cmp(res.Y) != 0 {
		t.Fatalf("public key does not match private key")
	}

	fmt.Println("CURVA-PrivMatch: ", res.Curva.Params().Name)
}

func TestMarshallBasicSz(t *testing.T) {

	res, err := fecdh.NewEcdhe(allSG)
	if err != nil || res == nil {
		t.Fatalf("CurveMe failed: %v", err)
	}

	bit := res.Curva.Params().BitSize
	coordLen := (bit + 7) / 8
	wantXY := coordLen * 2
	out, _ := res.Marshall()
	t.Logf("Curva: %v", res.Curva.Params().Name)
	wantTotal := 1 + 2 + 1 + 1 + wantXY
	if len(out) != wantTotal {
		t.Fatalf("got %d, want %d", len(out), wantTotal)
	}
}

func TestMarshallXY(t *testing.T) {

	res, err := fecdh.NewEcdhe(allSG)
	if err != nil || res == nil {
		t.Fatalf("CurveMe failed: %v", err)
	}

	t.Logf("Curva: %v", res.Curva.Params().Name)
	buffer, _ := res.Marshall()
	if buffer[0] != 0x03 {
		t.Fatal("named curve doesnt match")
	}

	fmt.Println("Grupo: ", names.SupportedGroups[res.Group])
	grupo := binary.BigEndian.Uint16(buffer[1:])
	if grupo != res.Group {
		t.Fatal("group value doesnt match")
	}

	lenn := int(buffer[3])
	if len(buffer[4:]) != lenn {
		t.Fatal("len doesnt match")
	}

	if buffer[4] != 0x04 {
		t.Fatal("uncompressed point doesnt match")
	}

	sz := int((lenn - 1) / 2)
	if len(buffer[5:]) != sz*2 {
		t.Fatalf("x,y len mismatch: %v VS %v\n", len(buffer[5:]), sz*2)
	}

	bx := new(big.Int).SetBytes(buffer[5 : 5+sz])
	by := new(big.Int).SetBytes(buffer[5+sz:])
	if bx.Cmp(res.X) != 0 {
		t.Fatal("X mismatch")
	}

	if by.Cmp(res.Y) != 0 {
		t.Fatal("Y mismatch")
	}

}

func TestMarshallRoundTrip(t *testing.T) {
	// Genera un punto real ECDHE
	res, err := fecdh.NewEcdhe(allSG)
	if err != nil || res == nil {
		t.Fatalf("CurveMe failed: %v", err)
	}

	buf1, _ := res.Marshall()
	e2, err := fecdh.Unmarshal(buf1)
	if err != nil {
		t.Fatalf("UnMarshall failed: %v", err)
	}

	buf2, _ := e2.Marshall()
	if !bytes.Equal(buf1, buf2) {
		t.Fatalf("roundtrip mismatch:\nbuf1=%X\nbuf2=%X", buf1, buf2)
	}

	if e2.Group != res.Group {
		t.Fatal("group mismatch")
	}

	if e2.X.Cmp(res.X) != 0 {
		t.Fatal("X mismatch")
	}

	if e2.Y.Cmp(res.Y) != 0 {
		t.Fatal("Y mismatch")
	}
}
