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
	GetFingerPrints() [][]byte
	GetAll() [][]*x509.Certificate
	Get([]byte) []*x509.Certificate
	GetBy(*CertOpts) []*x509.Certificate
	GetPrivateKey([]byte) crypto.PrivateKey
	SaSupport([]uint16, []byte) bool
	FingerPrint(*x509.Certificate) []byte
	Load(*CertPath) (*x509.Certificate, error)
}
