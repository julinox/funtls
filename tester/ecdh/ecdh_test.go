package ecdh

import (
	"crypto/x509"
	"fmt"
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

	res, err := fecdh.Curveame(allSG, &x509.Certificate{})
	if err != nil {
		t.Fatalf("expected error, got nil")
	}

	if nonSupportedSG[res.Group] {
		t.Fatalf("returned non supported group '%v'", res.Group)
	}

	fmt.Println("Curva NonSupp: ", res.Curva.Params().Name)
}

func TestCurveame_IsOnCurve(t *testing.T) {

	res, err := fecdh.Curveame(allSG, &x509.Certificate{})
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

	res, err := fecdh.Curveame(allSG, &x509.Certificate{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	X2, Y2 := res.Curva.ScalarBaseMult(res.Priv)
	if X2.Cmp(res.X) != 0 || Y2.Cmp(res.Y) != 0 {
		t.Fatalf("public key does not match private key")
	}

	fmt.Println("CURVA-PrivMatch: ", res.Curva.Params().Name)
}
