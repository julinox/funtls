package certificate

import (
	"crypto"
	"crypto/x509"
)

type CertPath struct {
	ChainPath string
	KeyPath   string
}

type CertOpts struct {
	IgnoreExpired bool
	DnsNames      []string
	KeyAlgorithm  x509.PublicKeyAlgorithm
}

type CertPKI interface {
	Print() string
	SaSupport([]uint16, []byte) bool
	GetAll() [][]*x509.Certificate
	Get([]byte) []*x509.Certificate
	GetBy(*CertOpts) []*x509.Certificate
	GetCertPKey([]byte) crypto.PrivateKey
	FingerPrint(*x509.Certificate) []byte
	Load(*CertPath) (*x509.Certificate, error)
}
