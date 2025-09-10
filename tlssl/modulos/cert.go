package modulos

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

type ModCerts interface {
	Name() string
	Print() string
	CNs() []string
	Load(*CertInfo) (*pki, error)
	Get(string) *x509.Certificate
	GetCertChain(string) []*x509.Certificate
	GetByCriteria(uint16, string) *x509.Certificate
	GetCertKey(*x509.Certificate) crypto.PrivateKey
}

type CertInfo struct {
	PathCert string
	PathKey  string
}

type pki struct {
	cn        string
	saSupport map[uint16]bool
	san       map[string]bool // Subject Alternative Names
	key       crypto.PrivateKey
	certChain []*x509.Certificate // 0 is the leaf
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
		newMod.lg.Infof("Certificate loaded: %s",
			newPki.certChain[0].Subject.CommonName)
	}

	if len(newMod.pkInfo) <= 0 {
		return nil, fmt.Errorf("no certificates loaded (%s)", myself)
	}

	return &newMod, nil
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

	key, err := loadPrivateKey2(ptr.PathKey)
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
	newPki.key = key
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
// - RSA-PSS (rsa_pss_*): a modern RSA signature scheme (Probabilistic Signature
//   Scheme). It adds randomized padding and is provably secure under stronger
//   assumptions. Mandatory in TLS 1.3, optional in TLS 1.2.
//
// Public key type in the certificate defines what is possible:
//
// - If the certificate contains a normal RSA key (OID rsaEncryption):
//   * It can be used with PKCS#1 v1.5 (rsa_pkcs1_*).
//   * It can also be used with PSS (rsa_pss_rsae_*).
//
// - If the certificate contains an RSA-PSS key (OID rsassaPss):
//   * It can only be used with PSS (rsa_pss_pss_*).
//   * PKCS#1 v1.5 is not allowed.
//
// In other words, the cert itself does not declare "I am pkcs1" or "I am pss".
// The cert just fixes the key type. From that, TLS derives which signature
// schemes are valid.

func (p *pki) setSignAlgoSupport() error {

	p.saSupport = make(map[uint16]bool)
	leaf := p.certChain[0]
	if leaf == nil || leaf.PublicKey == nil {
		return fmt.Errorf("invalid certificate or public key")
	}

	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("certificate does not allow digital signatures")
	}

	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.Size() < 128 {
			return fmt.Errorf("RSA public key size less than 128 bytes")
		}

		if isRSAPSSPublicKey(leaf.RawSubjectPublicKeyInfo) {
			fmt.Println("---------------------- ES PSSSSSS ------------------")
			return fmt.Errorf("RSA-PSS public key found, but RSA-PSS is not supported in this implementation")
		}

		p.saSupport[names.RSA_PKCS1_SHA256] = true
		p.saSupport[names.RSA_PKCS1_SHA384] = true
		p.saSupport[names.RSA_PKCS1_SHA512] = true
		p.saSupport[names.RSA_PSS_RSAE_SHA256] = true
		p.saSupport[names.RSA_PSS_RSAE_SHA384] = true

		if pub.Size() >= 130 {
			p.saSupport[names.RSA_PSS_RSAE_SHA512] = true
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
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}

			certs = append(certs, cert)
		}

		data = rest
	}

	return certs, nil
}

func loadPrivateKey2(path string) (*fcrypto.PrivateKey, error) {

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

	kk, err := fcrypto.ParsePKCS8PrivateKeyPSS(block.Bytes)
	if err != nil {
		return nil, err
	}

	return kk, nil
}

func loadPrivateKey(path string) (crypto.PrivateKey, error) {

	if path == "" {
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
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)

	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil

		default:
			return nil, fmt.Errorf("unknown private key type")
		}
	}

	return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
}

func validateKeyPair(cert *x509.Certificate, key crypto.PrivateKey) bool {

	if cert == nil || key == nil {
		return false
	}

	switch keyT := key.(type) {
	case *rsa.PrivateKey:
		//fmt.Printf("%x\n", keyT.PublicKey)
		//fmt.Println()
		fmt.Printf("%x\n", cert.PublicKey)
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
