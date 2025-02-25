package modulos

import (
	"fmt"

	sts "tlesio/tlssl/suites"

	"github.com/sirupsen/logrus"
)

type ModuloZ struct {
	Certs    ModCerts
	TLSSuite ModTLSSuite
	err      error // only for initialization
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

func (z *ModuloZ) InitTLSSuite(lg *logrus.Logger, suites []sts.Suite) error {

	if z.err != nil {
		return z.err
	}

	aux, err := NewModTLSSuite(lg)
	if aux == nil {
		return err
	}

	z.TLSSuite = aux
	for _, suite := range suites {
		if err := z.TLSSuite.RegisterSuite(suite); err != nil {
			lg.Error("Suite registry:", err)
			continue
		}

		lg.Info("Suite registered: ", suite.Name())
	}

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

	if z.TLSSuite == nil {
		return fmt.Errorf("module 'ModTLSSuite' not initialized")
	}

	return nil
}
