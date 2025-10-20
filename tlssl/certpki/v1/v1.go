package v1

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"maps"

	"github.com/julinox/funtls/systema"
	cert "github.com/julinox/funtls/tlssl/certpki"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/sirupsen/logrus"
)

type pki struct {
	cname       string
	fingerPrint []byte
	saSupport   map[uint16]bool // Suppoorted Algorithns
	san         map[string]bool // Subject Alternative Names
	key         crypto.PrivateKey
	chain       []*x509.Certificate // 0 is the leaf
}

type xCertPKI struct {
	info []*pki
	lg   *logrus.Logger
}

func NewV1(lg *logrus.Logger, paths []*cert.CertPath) (cert.CertPKI, error) {

	var cPki xCertPKI

	myself := systema.MyName()
	if lg == nil {
		return nil, fmt.Errorf("nil logger (%s)", myself)
	}

	if len(paths) <= 0 {
		return nil, fmt.Errorf("empty paths (%s)", myself)
	}

	cPki.lg = lg
	for _, p := range paths {
		cert, err := cPki.Load(p)
		if err != nil {
			cPki.lg.Errorf("error loading PKI (%v): %v", p.ChainPath, err)
			continue
		}

		cPki.lg.Infof("Loaded cert '%v' (%v)", cert.Subject.CommonName,
			cert.PublicKeyAlgorithm)
	}

	return &cPki, nil
}

func (x *xCertPKI) Print() string {

	var str string

	for i, pki := range x.info {
		var sans []string

		for s := range maps.Keys(pki.san) {
			sans = append(sans, s)
		}

		fp := hexToPointString(pki.fingerPrint[:8])
		if i < len(x.info)-1 {
			str += fmt.Sprintf("%s (%v) | %v | %s\n", pki.cname, fp,
				sans, printSASupport(pki.saSupport, ","))
		} else {
			str += fmt.Sprintf("%s (%v) | %v | %s", pki.cname, fp,
				sans, printSASupport(pki.saSupport, ","))
		}
	}

	return str
}
func (x *xCertPKI) SaSupport(sa []uint16, fingerpint []byte) bool {

	for _, p := range x.info {
		if !bytes.Equal(p.fingerPrint, fingerpint) {
			continue
		}

		for _, s := range sa {
			if p.saSupport[s] {
				return true
			}
		}
	}

	return false
}

func (x *xCertPKI) Get(fingerprint []byte) []*x509.Certificate {

	if len(fingerprint) == 0 {
		return nil
	}

	for _, pki := range x.info {
		if bytes.Equal(fingerprint, pki.fingerPrint) {
			return pki.chain
		}
	}

	return nil
}

// Select certificate that mntches by:
// - Dns Names (CNAME + SAN)
// - Public Key Algorithm
// - Ignore if certificate is expired
// - Any other parameter in "opts"
func (x *xCertPKI) GetBy(opts *cert.CertOpts) []*x509.Certificate {

	if opts == nil {
		return nil
	}

	for _, pki := range x.info {
		if len(opts.DnsNames) > 0 && !matchByname(opts.DnsNames, pki.san) {
			continue
		}

		if opts.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm &&
			opts.KeyAlgorithm != pki.chain[0].PublicKeyAlgorithm {
			continue
		}

		if !opts.IgnoreExpired && !certValidity(pki.chain[0]) {
			continue
		}

		return pki.chain
	}

	return nil
}

func (x *xCertPKI) Load(path *cert.CertPath) (*x509.Certificate, error) {

	var peca pki

	chain, err := loadCertificateChain(path.ChainPath)
	if err != nil {
		return nil, err
	}

	if len(chain) <= 0 {
		return nil, fmt.Errorf("no cert chain generated")
	}

	key, err := loadPrivateKey(path.KeyPath)
	if err != nil {
		return nil, err
	}

	if !validateKeyPair(chain[0], key) {
		return nil, fmt.Errorf("certificate and private key mismatch")
	}

	if err = certPreFlight(chain); err != nil {
		return nil, fmt.Errorf("certificate pre-flight check failed: %w", err)
	}

	peca.san = make(map[string]bool)
	peca.cname = chain[0].Subject.CommonName
	peca.key = key
	peca.chain = chain
	if err = peca.setSignAlgoSupport(); err != nil {
		return nil, err
	}

	peca.san[peca.cname] = true
	for _, san := range chain[0].DNSNames {
		peca.san[san] = true
	}

	peca.fingerPrint = certFingerPrint(peca.chain[0])
	x.info = append(x.info, &peca)
	return peca.chain[0], nil
}

func (x *xCertPKI) FingerPrint(cert *x509.Certificate) []byte {
	return certFingerPrint(cert)
}

// PKCS#1 v1.5 vs. RSA-PSS
//
// - PKCS#1 v1.5 (rsa_pkcs1_*): the "classic" RSA signature padding, widely used
//   in TLS 1.2 and earlier.
//
// - RSA-PSS (rsa_pss_*): a modern RSA signature scheme (Probabilistic
//   Signature Scheme). It adds randomized padding and is provably secure
//   under stronger assumptions. Mandatory in TLS 1.3, optional in TLS 1.2.
//
// A PSS certificate explicitly declares that the key must be used only for
// RSA-PSS signatures, and includes exact PSS parameters: hash algorithm,
// MGF1, hash, salt length, etc.
//
// In contrast, a "normal" RSA certificate does not include any parameters
// and does not specify any signature scheme — it can be used with either
// PKCS#1 v1.5 or PSS, and when PSS is used the choice of parameters is
// deferred to the protocol (e.g., TLS).

// Both certificates may contain structurally identical RSA keys (modulus + exponent).
// The difference lies purely in intent and constraints declared in the certificate.
// While applications are expected to enforce these usage rules, nothing cryptographically
// prevents extracting the key and using it for encryption or non-PSS signing.

// Public key type in the certificate defines what is possible:
//
// - If the certificate contains a normal RSA key (OID rsaEncryption):
//   - It can be used with PKCS#1 v1.5 (rsa_pkcs1_*).
//   - It can also be used with PSS (rsa_pss_rsae_*).
//
// - If the certificate contains an RSA-PSS key (OID rsassaPss):
//   - It can only be used with PSS (rsa_pss_pss_*).
//   - PKCS#1 v1.5 is not allowed.
func (p *pki) setSignAlgoSupport() error {

	p.saSupport = make(map[uint16]bool)
	leaf := p.chain[0]
	if leaf == nil || leaf.PublicKey == nil {
		return fmt.Errorf("invalid certificate or public key")
	}

	switch leaf.PublicKeyAlgorithm {
	case x509.RSA:
		if isRSAPSSPublicKey(leaf.RawSubjectPublicKeyInfo) {
			return fmt.Errorf("RSA-PSS public key found (not supported)")
		}

		aux, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid RSA public key type")
		}

		if aux.Size() < 128 {
			return fmt.Errorf("RSA public key size less than 128 bytes")
		}

		p.saSupport[names.RSA_PKCS1_SHA256] = true
		p.saSupport[names.RSA_PKCS1_SHA384] = true
		p.saSupport[names.RSA_PKCS1_SHA512] = true
		p.saSupport[names.RSA_PSS_RSAE_SHA256] = true
		p.saSupport[names.RSA_PSS_RSAE_SHA384] = true
		p.saSupport[names.RSA_PSS_RSAE_SHA512] = true
		p.saSupport[names.SHA224_RSA] = true

	case x509.DSA:
		p.saSupport[names.SHA224_DSA] = true
		p.saSupport[names.SHA384_DSA] = true
		p.saSupport[names.SHA512_DSA] = true

	case x509.ECDSA:
		if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
			switch pub.Curve {
			case elliptic.P256():
				p.saSupport[names.ECDSA_SECP256R1_SHA256] = true
			case elliptic.P384():
				p.saSupport[names.ECDSA_SECP384R1_SHA384] = true
			case elliptic.P521():
				p.saSupport[names.ECDSA_SECP521R1_SHA512] = true
			}
		}
	}

	return nil
}
