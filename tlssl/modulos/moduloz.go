package modulos

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

type ModuloZ struct {
	Certs        ModCerts
	CipherSuites ModCipherSuites
	err          error // only for initialization
}

func NewModuloZ() *ModuloZ {
	return &ModuloZ{}
}

func (z *ModuloZ) InitCerts(lg *logrus.Logger, paths []*CertPaths) error {

	if z.err != nil {
		return z.err
	}

	aux, err := NewModCerts(lg, paths)
	if aux == nil {
		return err
	}

	z.Certs = aux
	return nil
}

func (z *ModuloZ) InitCipherSuites(cfg *CipherSuiteConfig) error {

	if z.err != nil {
		return z.err
	}

	aux, err := NewModCipherSuites(cfg)
	if aux == nil {
		return err
	}

	z.CipherSuites = aux
	return nil
}

// Check if all modules are initialized
func (z *ModuloZ) CheckModInit() error {

	if z.err != nil {
		return z.err
	}

	if z.Certs == nil {
		return fmt.Errorf("module 'ModCerts' not initialized")
	}

	if z.CipherSuites == nil {
		return fmt.Errorf("module 'ModCipherSuites' not initialized")
	}

	return nil
}
