package ciphersuites

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strings"

	cpki "github.com/julinox/funtls/tlssl/certpki"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type suiteRequisites func(*x509.Certificate) bool

// CipherSuite related certs
type csrCert struct {
	group       uint16
	fingerPrint []byte
	name        string
}

type suiteBaseInfo struct {
	isClient     bool
	relatedcerts []*csrCert
	certPki      cpki.CertPKI
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

// Validates if certificate meets minimun requirements
// 'cps' function is a function that meets suite's individual
// or specific requirements
func certPreselect(opts *suite.SuiteOpts, sr suiteRequisites) *suiteBaseInfo {

	var sbi suiteBaseInfo

	sbi.relatedcerts = make([]*csrCert, 0)
	if opts.IsClient {
		sbi.isClient = true
		return &sbi
	}

	fingerPrints := opts.Pki.GetFingerPrints()
	if len(fingerPrints) == 0 {
		return nil
	}

	for _, fp := range fingerPrints {
		chain := opts.Pki.Get(fp)
		if len(chain) == 0 {
			continue
		}

		if !checkEKU(chain[0].ExtKeyUsage, x509.ExtKeyUsageAny) &&
			!checkEKU(chain[0].ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			continue
		}

		if sr != nil && sr(chain[0]) {
			sbi.relatedcerts = append(sbi.relatedcerts, &csrCert{
				group:       ecGroupName(chain[0]),
				fingerPrint: fp,
				name: fmt.Sprintf("%v (%v)", chain[0].Subject.CommonName,
					chain[0].PublicKeyAlgorithm),
			})
		}
	}

	return &sbi
}

// Validates if all certs in chain were signed with one
// of the given signature algorithms (SA list). RFC states
// that you must treat the SA list as the list of algorithms
// the peer is capable of handling (remember that validating
// a cert means checking its signature)
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

// Cert's EC-curve must be among SG list
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

// Check cert requirements for TLS_RSA_* suites
func rsaCertCheck(cert *x509.Certificate) bool {

	if cert.PublicKeyAlgorithm != x509.RSA {
		return false
	}

	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return false
	}

	return true
}

// Check cert requirements for TLS_ECDHE_* suites
func ecdsaCertCheck(cert *x509.Certificate) bool {

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return false
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}

	groupName := ecGroupName(cert)
	if groupName == names.NOGROUP {
		return false
	}

	return true
}

func printCertNameType(relatedcerts []*csrCert) string {

	var str string

	sz := len(relatedcerts)
	if sz == 0 {
		return ""
	}

	for i := 0; i < sz; i++ {
		str += relatedcerts[i].name
		if i < sz-1 {
			str += ","
		}
	}

	return str
}
