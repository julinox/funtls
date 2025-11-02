package ciphersuites

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

var sigAlgToSchemes = map[x509.SignatureAlgorithm][]uint16{
	x509.SHA256WithRSA:    {names.RSA_PKCS1_SHA256, names.RSA_PSS_RSAE_SHA256},
	x509.SHA384WithRSA:    {names.RSA_PKCS1_SHA384, names.RSA_PSS_RSAE_SHA384},
	x509.SHA512WithRSA:    {names.RSA_PKCS1_SHA512, names.RSA_PSS_RSAE_SHA512},
	x509.ECDSAWithSHA256:  {names.ECDSA_SECP256R1_SHA256},
	x509.ECDSAWithSHA384:  {names.ECDSA_SECP384R1_SHA384},
	x509.ECDSAWithSHA512:  {names.ECDSA_SECP521R1_SHA512},
	x509.SHA256WithRSAPSS: {names.RSA_PSS_PSS_SHA256},
	x509.SHA384WithRSAPSS: {names.RSA_PSS_PSS_SHA384},
	x509.SHA512WithRSAPSS: {names.RSA_PSS_PSS_SHA512},
	x509.PureEd25519:      {names.ED25519},
}

// Validates if all certs in chain were signed with one
// of the given signature algorithms (SA list)
func validateChainSignatures(chain []*x509.Certificate, sa []uint16) error {

	if len(chain) == 0 || len(sa) == 0 {
		return fmt.Errorf("no chain or  SA list")
	}

	saMap := saToMapSA(sa)
	for _, cert := range chain {
		valid := false
		for _, scheme := range sigAlgToSchemes[cert.SignatureAlgorithm] {
			if saMap[scheme] {
				valid = true
				break
			}
		}

		if !valid {
			return fmt.Errorf("chain cannot be validated by schemes list")
		}
	}

	return nil
}

func saToMapSA(sa []uint16) map[uint16]bool {

	var mapa map[uint16]bool

	mapa = make(map[uint16]bool)
	for _, a := range sa {
		mapa[a] = true
	}

	return mapa
}

func getECGroupName(cert *x509.Certificate) uint16 {

	if cert == nil || cert.PublicKeyAlgorithm != x509.ECDSA {
		return names.NOGROUP
	}

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return names.NOGROUP
	}

	switch pubKey.Curve {
	case elliptic.P256():
		return names.SECP256R1
	case elliptic.P384():
		return names.SECP384R1
	case elliptic.P521():
		return names.SECP521R1
	}

	return names.NOGROUP
}

// Check if certificate key's curve is compatible with given SG list
// Per RFC's standar ECDH SG's list is mandatory and must
// contain at least one matching curve to use on the KX
func ecdhSGCertMatch(match *suite.CertMatch) error {

	var curva uint16

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

	// For TLS 1.2 theres available only 3 NIST curves: secp256r1,
	// secp384r1 and secp521r1 (yeah nice try secp224r1).
	// So, if the certificate contains an ECDSA key then it must supports
	// one, and only one 'secp' curve
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("")
	}

	switch pub.Curve {
	case elliptic.P256():
		curva = names.SECP256R1
	case elliptic.P384():
		curva = names.SECP384R1
	case elliptic.P521():
		curva = names.SECP521R1
	}

	for _, g := range match.SG {
		if g == curva {
			return nil
		}
	}

	return fmt.Errorf("SG list is unsupported | %v", name)
}
