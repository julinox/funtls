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
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

const (
	_ECDSA_SECP256R1_SHA256 = 0x0403
	_ECDSA_SECP384R1_SHA384 = 0x0503
	_ECDSA_SECP521R1_SHA512 = 0x0603
	_ED25519                = 0x0807
	_ED448                  = 0x0808
	_RSA_PSS_PSS_SHA256     = 0x0809
	_RSA_PSS_PSS_SHA384     = 0x080A
	_RSA_PSS_PSS_SHA512     = 0x080B
	_RSA_PKCS1_SHA256       = 0x0401
	_RSA_PKCS1_SHA384       = 0x0501
	_RSA_PKCS1_SHA512       = 0x0601
	_RSA_PSS_RSAE_SHA256    = 0x0804
	_RSA_PSS_RSAE_SHA384    = 0x0805
	_RSA_PSS_RSAE_SHA512    = 0x0806
)

var _SignatureHashAlgorithms = map[uint16]string{
	_ECDSA_SECP256R1_SHA256: "ecdsa_secp256r1_sha256",
	_ECDSA_SECP384R1_SHA384: "ecdsa_secp384r1_sha384",
	_ECDSA_SECP521R1_SHA512: "ecdsa_secp521r1_sha512",
	_ED25519:                "ed25519",
	_ED448:                  "ed448",
	_RSA_PSS_PSS_SHA256:     "rsa_pss_pss_sha256",
	_RSA_PSS_PSS_SHA384:     "rsa_pss_pss_sha384",
	_RSA_PSS_PSS_SHA512:     "rsa_pss_pss_sha512",
	_RSA_PSS_RSAE_SHA256:    "rsa_pss_rsae_sha256",
	_RSA_PSS_RSAE_SHA384:    "rsa_pss_rsae_sha384",
	_RSA_PSS_RSAE_SHA512:    "rsa_pss_rsae_sha512",
	_RSA_PKCS1_SHA256:       "rsa_pkcs1_sha256",
	_RSA_PKCS1_SHA384:       "rsa_pkcs1_sha384",
	_RSA_PKCS1_SHA512:       "rsa_pkcs1_sha512",
}

type CertificatesData_1 struct {
	PathCert string
	PathKey  string
}

type CertificatesConfig struct {
	Lg    *logrus.Logger
	Certs []CertificatesData_1
}

type CertificatesData struct {
	Name      string
	Pkey      crypto.PrivateKey
	Cert      *x509.Certificate
	saSupport map[uint16]bool
}

type modulo0xFFFE struct {
	lg     *logrus.Logger
	config *CertificatesConfig
	pki    []*CertificatesData
}

func ModuloCertificates(cfg interface{}) (Modulo, error) {

	var modd modulo0xFFFE

	x509.ParsePKCS8PrivateKey(nil)
	data, ok := cfg.(CertificatesConfig)
	if !ok {
		return nil, fmt.Errorf("error casting Config0xFFFE")
	}

	if data.Lg == nil {
		return nil, fmt.Errorf("%v (%v)", systema.ErrNilLogger.Error(), "Modulo 0xFFFE")
	}

	modd.lg = data.Lg
	modd.config = &data
	modd.pki = make([]*CertificatesData, 0)
	for _, v := range data.Certs {
		data, err := modd.LoadData(v)
		if data == nil {
			modd.lg.Error("Error loading PKI: ", v.PathCert)
			continue
		}

		if err != nil {
			modd.lg.Errorf("Error loading PKI(%v): %v", v.PathCert, err.Error())
			continue
		}

		dataf := data.(*CertificatesData)
		dataf.setSASupport()
		modd.pki = append(modd.pki, dataf)
	}

	if len(modd.pki) == 0 {
		return nil, fmt.Errorf("no certificates loaded")
	}

	return &modd, nil
}

// Receive a signing algorithm and return a matching certificate
// Returns first certificate if no data is provided
func (e *modulo0xFFFE) Execute(data interface{}) interface{} {

	if data == nil {
		return e.pki[0]
	}

	dtt, ok := data.(uint16)
	if !ok {
		return nil
	}

	for _, v := range e.pki {
		if _, ok := v.saSupport[dtt]; ok {
			return v
		}
	}

	return nil
}

func (e *modulo0xFFFE) ID() uint16 {
	return 0xFFFE
}

func (e *modulo0xFFFE) Name() string {
	return ModuloName[e.ID()]
}

func (e *modulo0xFFFE) GetConfig() interface{} {
	return e.config
}

// Returns *Cert0xFFFE
func (e *modulo0xFFFE) LoadData(data interface{}) (interface{}, error) {

	var err error
	var newPki CertificatesData

	dt, ok := data.(CertificatesData_1)
	if !ok {
		return nil, systema.ErrInvalidData
	}

	newPki.Cert, err = loadCertificate(dt.PathCert)
	if err != nil {
		return nil, err
	}

	newPki.Pkey, err = loadPrivateKey(dt.PathKey)
	if err != nil {
		return nil, err
	}

	if !validateKeyPair(newPki.Cert, newPki.Pkey) {
		return nil, fmt.Errorf("invalid key pair")
	}

	newPki.Name = newPki.Cert.Subject.CommonName
	return &newPki, nil
}

func (e *modulo0xFFFE) Print() string {

	var str string

	for _, v := range e.pki {
		str += fmt.Sprintf("%v [%v]\n", v.Cert.Subject.CommonName,
			printSASupport(v.saSupport, ", "))
	}

	return str
}

func (e *modulo0xFFFE) PrintRaw(data []byte) string {
	return "-*-"
}

func (d *CertificatesData) setSASupport() {

	d.saSupport = make(map[uint16]bool)
	switch pub := d.Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		// RSA PKCS1
		d.saSupport[_RSA_PKCS1_SHA256] = true
		d.saSupport[_RSA_PKCS1_SHA384] = true
		d.saSupport[_RSA_PKCS1_SHA512] = true

		// RSA-PSS
		if pub.Size() >= 256 {
			d.saSupport[_RSA_PSS_RSAE_SHA256] = true
			d.saSupport[_RSA_PSS_RSAE_SHA384] = true
			d.saSupport[_RSA_PSS_RSAE_SHA512] = true
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
			result += _SignatureHashAlgorithms[sa]
			count++
			if count < total {
				result += separator
			}
		}
	}

	return result
}
