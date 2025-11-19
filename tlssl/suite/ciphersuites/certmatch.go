package ciphersuites

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/julinox/funtls/tlssl/names"
)

// CipherSuite related certs
type csrCert struct {
	group       uint16
	fingerPrint []byte
}

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

// For TLS 1.2 theres available only 3 NIST curves: secp256r1,
// secp384r1 and secp521r1 (yeah nice try secp224r1).
// So, if the certificate contains an ECDSA key then it must supports
// one, and only one 'secp' curve
func ecGroupName(cert *x509.Certificate) uint16 {

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

// La curva de la pubkey debe estar en SG
func sgMatchEcdsa(cert *x509.Certificate, sg []uint16) bool {

	if cert == nil {
		return false
	}

	groupName := ecGroupName(cert)
	if groupName == names.NOGROUP {
		return false
	}

	for _, g := range sg {
		if groupName == g {
			return true
		}
	}

	return false
}

func sgCheck(groupName uint16, sg []uint16) bool {

	if len(sg) == 0 {
		return true
	}

	for _, n := range sg {
		if groupName == n {
			return true
		}
	}

	return false
}

func checkEKU(eku []x509.ExtKeyUsage, ku x509.ExtKeyUsage) bool {

	if len(eku) == 0 {
		return false
	}

	for _, e := range eku {
		if e == ku {
			return true
		}
	}

	return false
}

func matchSniSan(sniList []string, sans []string, cn string) bool {

	if len(sniList) == 0 {
		return true
	}

	sni := sniList[0]
	if sni == "" {
		return true
	}

	for _, san := range sans {
		if sniSanVs(sni, san) {
			return true
		}
	}

	if cn != "" && sniSanVs(sni, cn) {
		return true
	}

	return false
}

func sniSanVs(sni, san string) bool {

	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	san = strings.ToLower(strings.TrimSuffix(san, "."))
	if !strings.Contains(san, "*") {
		return sni == san
	}

	sniParts := strings.Split(sni, ".")
	sanParts := strings.Split(san, ".")

	// a*.example.com
	if sanParts[0] != "*" {
		return false
	}

	// avoid *.com, *.net, etc
	if len(sanParts) < 3 {
		return false
	}

	if len(sniParts) != len(sanParts) {
		return false
	}

	for i := 1; i < len(sanParts); i++ {
		if sniParts[i] != sanParts[i] {
			return false
		}
	}

	return true
}
