package ciphersuites

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type x0xC02B struct {
}

func NewEcdheEcdsaAes128GcmSha256() suite.Suite {
	return &x0xC02B{}
}

func (x *x0xC02B) ID() uint16 {
	return 0xC02B
}

func (x *x0xC02B) Name() string {
	return suite.CipherSuiteNames[x.ID()]
}

func (x *x0xC02B) Info() *suite.SuiteInfo {

	return &suite.SuiteInfo{
		Mac:         names.MAC_HMAC,
		CipherType:  names.CIPHER_AEAD,
		Hash:        names.HASH_SHA256,
		HashSize:    32,
		Cipher:      names.CIPHER_AES,
		KeySize:     16,
		KeySizeHMAC: 32,
		IVSize:      12,
		Auth:        names.SIG_ECDSA,
		KeyExchange: names.KX_ECDHE,
	}
}

func (x *x0xC02B) Cipher(ctx *suite.SuiteContext) ([]byte, error) {
	return nil, fmt.Errorf("0xC02B Cipher not implemented")
}

func (x *x0xC02B) CipherNot(ctx *suite.SuiteContext) ([]byte, error) {
	return nil, fmt.Errorf("0xC02B CipherNot not implemented")
}

func (x *x0xC02B) MacMe(data, hashKey []byte) ([]byte, error) {
	return nil, fmt.Errorf("0xC02B Macintosh not implemented")
}

func (x *x0xC02B) HashMe(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("0xC02B HashMe not implemented")
}

func (x *x0xC02B) AcceptsCert(match *suite.SuiteMatch) error {

	if match == nil || match.Pki == nil {
		return fmt.Errorf("%v | no match params", x.Name())
	}

	if err := ecdhSGCertMatch(match); err != nil {
		return fmt.Errorf("%v | %v", x.Name(), err)
	}

	if err := ecdsaSACertMatch(match); err != nil {
		return fmt.Errorf("%v | %v", x.Name(), err)
	}

	return nil
}

// check if cert's public key is ecdsa
// check cert's curve agaisnt SA list
// check if cert is signed by a algorithm with SA list
func ecdsaSACertMatch(match *suite.SuiteMatch) error {

	if match == nil {
		return fmt.Errorf("nil suiteMatch")
	}

	chain := match.Pki.Get(match.FingerPrint)
	if len(chain) == 0 {
		return fmt.Errorf("no certificate chain")
	}

	name := fmt.Sprintf("%v (%v)", chain[0].Subject.CommonName,
		chain[0].PublicKeyAlgorithm)

	if chain[0].PublicKeyAlgorithm != x509.ECDSA {
		return fmt.Errorf("public key not ECDSA | %v", name)
	}

	if !match.Pki.SaSupport(match.SA, match.FingerPrint) {
		return fmt.Errorf("unsupported SA list | %v", name)
	}

	// Esta firmado por ?
	fmt.Println("Firmado: ", chain[0].SignatureAlgorithm)
	return nil
}

// Check if given certificate key's curve is compatible
// with given supported groups list.
// Per RFC's standar ECDH SG's list is mandatory (since that list
// the one that enables the curve)
func ecdhSGCertMatch(match *suite.SuiteMatch) error {

	var certGroup uint16

	if match == nil {
		return fmt.Errorf("nil suiteMatch")
	}

	chain := match.Pki.Get(match.FingerPrint)
	if len(chain) == 0 {
		return fmt.Errorf("no certificate chain")
	}

	name := fmt.Sprintf("%v (%v)", chain[0].Subject.CommonName,
		chain[0].PublicKeyAlgorithm)
	if len(match.SG) == 0 {
		return fmt.Errorf("no SG list given | %v", name)
	}

	publicKey, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("no ecdsa key | %v", name)
	}

	switch publicKey.Curve {
	case elliptic.P224():
		certGroup = names.SECP224R1
	case elliptic.P256():
		certGroup = names.SECP256R1
	case elliptic.P384():
		certGroup = names.SECP384R1
	case elliptic.P521():
		certGroup = names.SECP521R1
	default:
		return fmt.Errorf("no ecdsa curve | %v", name)
	}

	for _, g := range match.SG {
		if g == certGroup {
			return nil
		}
	}

	return fmt.Errorf("SG list is unsupported | %v", name)
}
