package modulos

import (
	sts "github.com/julinox/funtls/tlssl/suite"

	"github.com/sirupsen/logrus"
)

type ModuloZ struct {
	Certs    ModCerts
	TLSSuite ModTLSSuite
}

func NewModuloZ() *ModuloZ {
	return &ModuloZ{}
}

func (z *ModuloZ) LoadCertificates() {
}

/*func (z *ModuloZ) InitCerts(lg *logrus.Logger, paths []*CertPaths) error {

	aux, err := NewModCerts2(paths)
	if aux == nil {
		return err
	}

	z.Certs = aux
	return nil
}*/

func (z *ModuloZ) InitTLSSuite(lg *logrus.Logger, suites []sts.Suite) error {

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
