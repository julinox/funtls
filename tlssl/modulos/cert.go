package modulos

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/julinox/funtls/systema"
	fcrypto "github.com/julinox/funtls/tlssl/crypto"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

type CertInfo struct {
	PathCert string
	PathKey  string
}

type CertOpts struct {
	Sni    string
	SA     []uint16
	CsInfo *suite.SuiteInfo
}

type pki struct {
	cn        string
	saSupport map[uint16]bool
	san       map[string]bool // Subject Alternative Names
	key       crypto.PrivateKey
	certChain []*x509.Certificate // 0 is the leaf
}

type ModCerts interface {
	Name() string
	Print() string
	CNs() []string
	Load(*CertInfo) (*pki, error)
	Get(string) *x509.Certificate
	GetHSCert(*CertOpts) (*x509.Certificate, error)
	GetCertChain(string) []*x509.Certificate
	GetByCriteria(uint16, string) *x509.Certificate
	GetCertKey(*x509.Certificate) crypto.PrivateKey
}

type _xModCerts struct {
	lg     *logrus.Logger
	pkInfo []*pki
}

// Load all certificates and private keys
func NewModCerts(lg *logrus.Logger, certs []*CertInfo) (ModCerts, error) {

	var newMod _xModCerts

	myself := systema.MyName()
	if lg == nil {
		return nil, fmt.Errorf("nil logger (%s)", myself)
	}

	if len(certs) <= 0 {
		return nil, fmt.Errorf("empty paths (%s)", myself)
	}

	if len(certs) <= 0 {
		return nil, fmt.Errorf("empty certificates(%s)", myself)
	}

	newMod.lg = lg
	newMod.pkInfo = make([]*pki, 0)
	for _, p := range certs {
		newPki, err := newMod.Load(p)
		if err != nil {
			newMod.lg.Errorf("error loading PKI (%v): %v", p.PathCert, err)
			continue
		}

		newMod.pkInfo = append(newMod.pkInfo, newPki)
		newMod.lg.Infof("Certificate loaded: %s (PKA: %s)",
			newPki.certChain[0].Subject.CommonName,
			newPki.certChain[0].PublicKeyAlgorithm.String())
	}

	if len(newMod.pkInfo) <= 0 {
		return nil, fmt.Errorf("no certificates loaded (%s)", myself)
	}

	return &newMod, nil
}

// Match certificate by CipherSuite, SNI and Signature Algorithm
func (m *_xModCerts) GetHSCert(opts *CertOpts) (*x509.Certificate, error) {

	var certo *x509.Certificate

	for _, i := range m.pkInfo {
		if getHSCertKX(opts.CsInfo, i.certChain[0]) &&
			getHSCertSign(opts.CsInfo, i.certChain[0]) &&
			getHSCertSni(opts.Sni, i.certChain[0]) {
			for _, sa := range opts.SA {
				fmt.Printf("%v | %v\n", names.SignHashAlgorithms[sa],
					i.saSupport[sa])

			}
			certo = i.certChain[0]
			break
		}
	}

	return certo, nil
}

func (m *_xModCerts) Name() string {
	return "Certificate_Handler"
}

func (m *_xModCerts) Load(ptr *CertInfo) (*pki, error) {

	var newPki pki

	chain, err := loadCertificate(ptr.PathCert)
	if err != nil {
		return nil, err
	}

	if len(chain) <= 0 {
		return nil, fmt.Errorf("no certificate found")
	}

	key, err := loadPrivateKey(ptr.PathKey)
	if err != nil {
		return nil, err
	}

	if !validateKeyPair(chain[0], key.PrivKey) {
		return nil, fmt.Errorf("certificate and private key mismatch")
	}

	if err = certPreFlight(chain); err != nil {
		return nil, fmt.Errorf("certificate pre-flight check failed: %w", err)
	}

	newPki.san = make(map[string]bool)
	newPki.cn = chain[0].Subject.CommonName
	newPki.key = key.PrivKey
	newPki.certChain = chain
	if err = newPki.setSignAlgoSupport(); err != nil {
		return nil, err
	}

	newPki.san[newPki.cn] = true
	for _, san := range chain[0].DNSNames {
		newPki.san[san] = true
	}

	return &newPki, nil
}

func (m *_xModCerts) CNs() []string {

	cns := make([]string, 0)
	for _, pki := range m.pkInfo {
		cns = append(cns, pki.cn)
	}

	return cns
}

func (m *_xModCerts) Get(cn string) *x509.Certificate {

	var certCopy x509.Certificate

	for _, pki := range m.pkInfo {
		if strings.EqualFold(pki.cn, cn) {
			certCopy = *pki.certChain[0]
			return &certCopy
		}
	}

	return nil
}

// Criterias are Signature Algorithm (0 means no criteria) and
// CN (Common name) or DNS name (empty string means no name)
// Returns the first certificate found when no criteria is used
func (m *_xModCerts) GetByCriteria(sa uint16, cn string) *x509.Certificate {

	var certCopy x509.Certificate

	for _, pki := range m.pkInfo {
		if sa != 0 && (!pki.saSupport[sa]) {
			continue
		}

		// 'cn' is in the SAN list (set at Load)
		if cn != "" && !pki.san[cn] {
			continue
		}

		certCopy = *pki.certChain[0]
		return &certCopy
	}

	return nil
}

func (m *_xModCerts) GetCertKey(cert *x509.Certificate) crypto.PrivateKey {

	for _, pki := range m.pkInfo {
		if pki.certChain[0].Equal(cert) {
			return pki.key
		}
	}

	return nil
}

func (m *_xModCerts) GetCertChain(cn string) []*x509.Certificate {

	for _, pki := range m.pkInfo {
		if strings.EqualFold(pki.cn, cn) {
			return pki.certChain
		}
	}

	return []*x509.Certificate{}
}

// Print certs info
func (m *_xModCerts) Print() string {

	var str string

	for i, pki := range m.pkInfo {
		if i < len(m.pkInfo)-1 {
			str += fmt.Sprintf("%s | %s | %s\n", pki.cn, maps.Keys(pki.san),
				printSASupport(pki.saSupport, ","))
		} else {
			str += fmt.Sprintf("%s | %s | %s\n", pki.cn, maps.Keys(pki.san),
				printSASupport(pki.saSupport, ","))
		}
	}

	return str
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
	leaf := p.certChain[0]
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

func loadCertificate(path string) ([]*x509.Certificate, error) {

	var err error
	var certs []*x509.Certificate

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := fcrypto.ParseCertificatePSS(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}

			certs = append(certs, cert)
		}

		data = rest
	}

	return certs, nil
}

func loadPrivateKey(path string) (*fcrypto.PrivateKey, error) {

	var pKey *fcrypto.PrivateKey

	if path == "nil" {
		return nil, fmt.Errorf("empty path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
	case "EC PRIVATE KEY":
	case "PRIVATE KEY":
		pKey, err = fcrypto.ParsePKCS8PrivateKeyPSS(block.Bytes)

	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		return nil, err
	}

	return pKey, nil
}

func validateKeyPair(cert *x509.Certificate, key crypto.PrivateKey) bool {

	if cert == nil || key == nil {
		return false
	}

	switch keyT := key.(type) {
	case *rsa.PrivateKey:
		return keyT.PublicKey.Equal(cert.PublicKey)

	case *ecdsa.PrivateKey:
		return keyT.PublicKey.Equal(cert.PublicKey)
	}

	return false
}

func certPreFlight(chain []*x509.Certificate) error {

	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	leaf := chain[0]
	if leaf == nil || leaf.PublicKey == nil {
		return fmt.Errorf("invalid leaf certificate")
	}

	if leaf.IsCA {
		return fmt.Errorf("leaf certificate is a CA certificate")
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("leaf certificate not valid yet")
	}

	if now.After(leaf.NotAfter) {
		return fmt.Errorf("leaf certificate expired")
	}

	for i := 0; i+1 < len(chain); i++ {
		child, parent := chain[i], chain[i+1]
		if !parent.IsCA {
			return fmt.Errorf("parent certificate is not a CA certificate")
		}

		if parent.KeyUsage != 0 &&
			(parent.KeyUsage&x509.KeyUsageCertSign) == 0 {
			return fmt.Errorf("parent certificate does not allow signing")
		}

		if now.Before(parent.NotBefore) || now.After(parent.NotAfter) {
			return fmt.Errorf("intermediate '%v' not valid at current time",
				parent.Subject.CommonName)
		}

		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("bad signature: child %v ← parent %v: %v",
				child.Subject.CommonName, parent.Subject.CommonName, err)
		}
	}

	if len(leaf.ExtKeyUsage) > 0 {
		ok := false
		for _, eku := range leaf.ExtKeyUsage {
			if eku == x509.ExtKeyUsageServerAuth {
				ok = true
				break
			}
		}

		if !ok {
			return fmt.Errorf("leaf doesn't have 'ExtKeyUsageServerAuth'")
		}
	}

	return nil
}

func getHSCertKX(info *suite.SuiteInfo, cert *x509.Certificate) bool {

	if info == nil || cert == nil {
		return false
	}

	switch info.KeyExchange {
	case names.KX_RSA:
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 ||
			cert.PublicKeyAlgorithm != x509.RSA {
			return false
		}
	case names.KX_DHE:
	case names.KX_ECDHE:
		break
	default:
		return false
	}

	return true
}

func getHSCertSign(info *suite.SuiteInfo, cert *x509.Certificate) bool {

	if info == nil || cert == nil {
		return false
	}

	// For RSA key exchange theres no signature in the handshake
	if info.KeyExchange != names.KX_RSA &&
		cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}

	switch info.Auth {
	case names.SIG_RSA:
		if cert.PublicKeyAlgorithm != x509.RSA {
			return false
		}
	case names.SIG_DSS:
		if cert.PublicKeyAlgorithm != x509.DSA {
			return false
		}
	case names.SIG_ECDSA:
		if cert.PublicKeyAlgorithm != x509.ECDSA {
			return false
		}
	default:
		return false
	}

	return true
}

func getHSCertSni(sni string, cert *x509.Certificate) bool {

	if cert == nil {
		return false
	}

	if sni == "" {
		return true
	}

	for _, n := range cert.DNSNames {
		if strings.EqualFold(n, sni) {
			return true
		}
	}

	if strings.EqualFold(cert.Subject.CommonName, sni) {
		return true
	}

	return false
}

func isRSAPSSPublicKey(spki []byte) bool {

	pss := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	var aux struct {
		Algo   pkix.AlgorithmIdentifier
		BitStr asn1.BitString
	}

	if _, err := asn1.Unmarshal(spki, &aux); err != nil {
		return false
	}

	return aux.Algo.Algorithm.Equal(pss)
}

func printSASupport(saSupport map[uint16]bool, separator string) string {

	var result string

	count := 0
	total := len(saSupport)
	for sa, supported := range saSupport {
		if supported {
			result += names.SignHashAlgorithms[sa]
			count++
			if count < total {
				result += separator
			}
		}
	}

	return result
}
