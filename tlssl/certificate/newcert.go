package certificate

import (
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
	Get([]byte) *x509.Certificate
	//GetBy(*CertOpts) *x509.Certificate
	//GetChain([]byte) []*x509.Certificate
	//SaSupport([]uint16) bool
	Load(*CertPath) (*x509.Certificate, error)
	Print() string
}
