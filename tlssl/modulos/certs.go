package modulos

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/julinox/funtls/systema"
	ex "github.com/julinox/funtls/tlssl/extensions"

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
	cert      *x509.Certificate
	certChain []*x509.Certificate
}

type _xModCerts struct {
	lg     *logrus.Logger
	pkInfo []*pki
}

// Load all certificates and private keys
/*func NewModCertss(lg *logrus.Logger, paths []*CertInfo) (ModCerts, error) {

	var newMod _xModCerts

	if lg == nil {
		return nil, systema.ErrNilLogger
	}

	if len(paths) <= 0 {
		return nil, systema.ErrInvalidData
	}

	newMod.lg = lg
	newMod.pkInfo = make([]*pki, 0)
	for _, p := range paths {
		newPki, err := newMod.Load(p)
		if err != nil {
			newMod.lg.Error("error loading PKI: ", p.PathCert)
			continue
		}

		newMod.pkInfo = append(newMod.pkInfo, newPki)
		newMod.lg.Debugf("Certificate loaded: %s",
			newPki.cert.Subject.CommonName)
	}

	lg.Info("Module loaded: ", newMod.Name())
	return &newMod, nil
}*/

func NewModCerts2(lg *logrus.Logger, certs []*CertInfo) (ModCerts, error) {

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
			newMod.lg.Error("error loading PKI: ", p.PathCert)
			continue
		}

		newMod.pkInfo = append(newMod.pkInfo, newPki)
		newMod.lg.Infof("Certificate loaded: %s",
			newPki.certChain[0].Subject.CommonName)
	}

	return &newMod, nil
}

func (m *_xModCerts) Name() string {
	return "Certificate_Handler"
}

func (m *_xModCerts) Load(ptr *CertInfo) (*pki, error) {

	var newPki pki

	chain, err := loadCertificate2(ptr.PathCert)
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

	if !validateKeyPair(chain[0], key) {
		return nil, fmt.Errorf("certificate and private key mismatch")
	}

	newPki.san = make(map[string]bool)
	newPki.cn = chain[0].Subject.CommonName
	newPki.key = key
	newPki.certChain = chain
	newPki.setSignAlgoSupport()
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
			certCopy = *pki.cert
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
		fmt.Println("SA Name1: ", sa)
		if sa != 0 && (!pki.saSupport[sa]) {
			continue
		}

		fmt.Println("SA Name2: ", sa)
		// 'cn' is in the SAN list (set at Load)
		if cn != "" && !pki.san[cn] {
			continue
		}

		fmt.Println("SA Name3: ", sa)
		certCopy = *pki.cert
		return &certCopy
	}

	return nil
}

func (m *_xModCerts) GetCertKey(cert *x509.Certificate) crypto.PrivateKey {

	for _, pki := range m.pkInfo {
		if pki.cert.Equal(cert) {
			return pki.key
		}
	}

	return nil
}

// func (m *_xModCerts) GetCertChain(cert *x509.Certificate) []*x509.Certificate {
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

func (p *pki) setSignAlgoSupport() {

	p.saSupport = make(map[uint16]bool)
	switch pub := p.certChain[0].PublicKey.(type) {
	case *rsa.PublicKey:
		// RSA PKCS1
		p.saSupport[ex.RSA_PKCS1_SHA256] = true
		p.saSupport[ex.RSA_PKCS1_SHA384] = true
		p.saSupport[ex.RSA_PKCS1_SHA512] = true

		// RSA-PSS
		if pub.Size() >= 256 {
			p.saSupport[ex.RSA_PSS_RSAE_SHA256] = true
			p.saSupport[ex.RSA_PSS_RSAE_SHA384] = true
			p.saSupport[ex.RSA_PSS_RSAE_SHA512] = true
		}
	}
}

func loadCertificate2(path string) ([]*x509.Certificate, error) {

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

/*func loadCertificate(path string) (*x509.Certificate, error) {

	if path == "" {
		return nil, fmt.Errorf("empty path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}*/

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
		return keyT.PublicKey.Equal(cert.PublicKey)

	case *ecdsa.PrivateKey:
		return keyT.PublicKey.Equal(cert.PublicKey)
	}

	return false
}

func printSASupport(saSupport map[uint16]bool, separator string) string {

	var result string

	count := 0
	total := len(saSupport)
	for sa, supported := range saSupport {
		if supported {
			result += ex.SignHashAlgorithms[sa]
			count++
			if count < total {
				result += separator
			}
		}
	}

	return result
}
