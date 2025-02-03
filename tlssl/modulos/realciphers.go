package modulos

import (
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

type ModCipherSuites interface {
	Name() string
	Load()
}

type CipherSuiteConfig struct {
	ClientWeight int
	ServerWeight int
	Tax          uint16 //Force the use of a specific algorithm
	Lg           *logrus.Logger
}

type xModCipherSuites struct {
	lg        *logrus.Logger
	supported map[uint16]int
	config    *CipherSuiteConfig
}

func NewModCipherSuites(cfg *CipherSuiteConfig) (*xModCipherSuites, error) {

	var newCS xModCipherSuites

	if cfg == nil || cfg.Lg == nil {
		return nil, systema.ErrNilParams
	}

	newCS.lg = cfg.Lg
	newCS.config = cfg
	newCS.supported = make(map[uint16]int)
	if cfg.Tax != 0 {
		newCS.supported[cfg.Tax] = 1

	} else {
		for algo, preference := range SupportedCiphersSuite {
			newCS.supported[algo] = preference
		}
	}

	newCS.lg.Info("Module loaded: ", newCS.Name())
	return &newCS, nil
}

func (c *xModCipherSuites) Name() string {
	return "cipher_suites"
}

func (c *xModCipherSuites) Load() {
}
