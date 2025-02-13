package modulos

import (
	"tlesio/systema"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

// The algorithm for selecting cipher-suite algorithms will use this formula:
// Score = ClientWeight ⋅ ClientPosition + ServerWeight ⋅ ServerPriority

// The weights can be adjusted through the configuration to favor one
// algorithm over another. This allows for flexible prioritization based
// on specific client and server requirements.

// Also you can force a specific algorithm using 'tax' option

var CiphersSuiteSupported = map[uint16]int{
	0x003D: 1, // "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x009E: 2, // "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	//0x0067: 3, // "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0xCCAA: 3, // "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

type ModCipherSuites interface {
	Name() string
	ChooseCS([]uint16) uint16
	//GetSuite(uint16) (*Suite, error)
	LoadData([]byte) (*CipherSuiteData, error)
}

type CipherSuiteConfig struct {
	ClientWeight int
	ServerWeight int
	Tax          uint16 //Force the use of a specific algorithm
	Lg           *logrus.Logger
}

type CipherSuiteData struct {
	Len   uint16
	Algos []uint16
}

type xModCipherSuites struct {
	lg        *logrus.Logger
	supported map[uint16]int
	config    *CipherSuiteConfig
}

func NewModCipherSuites(cfg *CipherSuiteConfig) (ModCipherSuites, error) {

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
		for algo, preference := range CiphersSuiteSupported {
			newCS.supported[algo] = preference
		}
	}

	newCS.lg.Info("Module loaded: ", newCS.Name())
	return &newCS, nil
}

func (x *xModCipherSuites) Name() string {
	return "Cipher_Suites"
}

func (x *xModCipherSuites) ChooseCS(clientList []uint16) uint16 {

	var neo uint16

	if len(clientList) <= 0 || len(x.supported) <= 0 {
		return 0
	}

	count := 1
	lighter := ^uint16(0)
	for _, algo := range clientList {
		if x.supported[algo] == 0 {
			continue
		}

		if (x.config.ServerWeight*x.supported[algo])+
			(x.config.ClientWeight*count) < int(lighter) {
			neo = algo
		}
	}

	return neo
}

func (x *xModCipherSuites) LoadData(buffer []byte) (*CipherSuiteData, error) {

	var cs CipherSuiteData

	if buffer == nil || len(buffer) <= 0 {
		return nil, systema.ErrNilParams
	}

	cs.Len = uint16(buffer[0])<<8 | uint16(buffer[1])
	if len(buffer) < int(cs.Len*2) {
		return nil, systema.ErrInvalidData
	}

	cs.Algos = make([]uint16, cs.Len)
	for i := 0; i < int(cs.Len); i++ {
		cs.Algos[i] = uint16(buffer[i+2])<<8 | uint16(buffer[i+3])
	}

	return &cs, nil
}

func (x *xModCipherSuites) Print() string {
	return AlgosToName(0xFFFF, maps.Keys(x.supported))
}

func (x *xModCipherSuites) PrintRaw(data []byte) string {

	var str string
	var offset uint16 = 2

	len := uint16(data[0])<<8 | uint16(data[1])/2
	for i := 0; i < int(len); i++ {
		str += "\n" + AlgoToName(0xFFFF,
			uint16(data[offset])<<8|uint16(data[offset+1]))
		offset += 2
	}

	return str
}
