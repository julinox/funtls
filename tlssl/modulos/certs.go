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
	"tlesio/systema"
	ex "tlesio/tlssl/interfaces/extensions"

	"github.com/sirupsen/logrus"
)

type Criteria func(*pki) bool
type ModCerts interface {
	Name() string
	Load(*CertPaths) (*pki, error)
	GetAll() []*x509.Certificate
	GetByCriteria(...Criteria) (*x509.Certificate, error)
}

type CertPaths struct {
	PathCert string
	PathKey  string
}

type MsgCertificate struct {
	Length uint32
	Cert   []byte
}

type pki struct {
	name      string
	saSupport map[uint16]bool
	key       crypto.PrivateKey
	cert      *x509.Certificate
}

type _xModCerts struct {
	lg     *logrus.Logger
	pkInfo []*pki
}

// Load all certificates and private keys
func NewModCerts(lg *logrus.Logger, paths []*CertPaths) (ModCerts, error) {

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
}

func (m *_xModCerts) Name() string {
	return "Certificate_Handler"
}

func (m *_xModCerts) Load(ptr *CertPaths) (*pki, error) {

	var newPki pki

	cc, err := loadCertificate(ptr.PathCert)
	if err != nil {
		return nil, err
	}

	key, err := loadPrivateKey(ptr.PathKey)
	if err != nil {
		return nil, err
	}

	if !validateKeyPair(cc, key) {
		return nil, fmt.Errorf("certificate and private key mismatch")
	}

	newPki.name = cc.Subject.CommonName
	newPki.key = key
	newPki.cert = cc
	newPki.setSignAlgoSupport()
	return &newPki, nil
}

func (m *_xModCerts) GetAll() []*x509.Certificate {

	certs := make([]*x509.Certificate, 0)
	for _, pki := range m.pkInfo {
		certs = append(certs, pki.cert)
	}

	return certs
}

func (m *_xModCerts) GetByCriteria(cr ...Criteria) (*x509.Certificate, error) {

	for _, pki := range m.pkInfo {
		matches := true
		for _, criterion := range cr {
			if !criterion(pki) {
				matches = false
				break
			}
		}

		if matches {
			return pki.cert, nil
		}
	}

	return nil, fmt.Errorf("no matching certificate found")
}

func (p *pki) setSignAlgoSupport() {

	p.saSupport = make(map[uint16]bool)
	switch pub := p.cert.PublicKey.(type) {
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

func loadCertificate(path string) (*x509.Certificate, error) {

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
			result += ex.SignatureHashAlgorithms[sa]
			count++
			if count < total {
				result += separator
			}
		}
	}

	return result
}

func CriterionCN(cn string) func(*pki) bool {

	return func(pki *pki) bool {
		return strings.EqualFold(pki.cert.Subject.CommonName, cn)
	}
}

func CriterionSignAlgo(algo uint16) func(*pki) bool {

	return func(pki *pki) bool {
		return pki.saSupport[algo]
	}
}
