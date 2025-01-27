package modulos

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

// Load certificates
type Cert struct {
	Name       string
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

type CertInfo struct {
	PathCert string
	PathKey  string
}

type modulo0xFFFE struct {
	certs []Cert
	lg    *logrus.Logger
}

type Config0xFFFE struct {
	Lg    *logrus.Logger
	Certs []CertInfo // Paths to certificates
}

type Data0xFFFE struct {
}

func InitModule0xFFFE(cfg interface{}) (Modulo, error) {

	data, ok := cfg.(Config0xFFFE)
	if !ok {
		return nil, fmt.Errorf("error casting Config0xFFFE")
	}

	if data.Lg == nil {
		return nil, fmt.Errorf("%v (%v)", systema.ErrNilLogger.Error(), "Modulo 0xFFFE")
	}

	for _, v := range data.Certs {
		absPath, err := filepath.Abs(v.PathCert)
		if err != nil {
			return nil, fmt.Errorf("error getting absolute path: %v", err)
		}

		fmt.Println(absPath)
	}

	return &modulo0xFFFE{}, nil
}

func (e *modulo0xFFFE) Execute(data interface{}) interface{} {

	return nil
}

func (e *modulo0xFFFE) ID() uint16 {
	return 0xFFFE
}

func (e *modulo0xFFFE) Name() string {
	return ModuloName[e.ID()]
}

func (e *modulo0xFFFE) SetConfig(cfg interface{}) bool {
	return true
}

func (e *modulo0xFFFE) GetConfig() interface{} {
	return nil
}

func (e *modulo0xFFFE) LoadData(data []byte) interface{} {
	return nil
}

func (e *modulo0xFFFE) Print() string {
	return ""
}

func (e *modulo0xFFFE) PrintRaw(data []byte) string {
	return ""
}
