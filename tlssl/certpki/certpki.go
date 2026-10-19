package certificate

import (
	"crypto"
	"crypto/x509"
)

type CertPath struct {
	ChainPath string
	KeyPath   string
}

type CertPKI interface {
	Print() string
	GetFingerPrints() [][]byte
	GetAll() [][]*x509.Certificate
	Get([]byte) []*x509.Certificate
	GetPrivateKey([]byte) crypto.PrivateKey
	GetSigner([]byte) crypto.Signer
	//SaSupport([]uint16, []byte) bool
	GetSaSupport([]byte) map[uint16]bool
	FingerPrint(*x509.Certificate) []byte
	Load(*CertPath) (*x509.Certificate, error)
}
