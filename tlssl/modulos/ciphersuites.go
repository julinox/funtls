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
var CipherSuiteNames = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA",
	0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
	0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x003B: "TLS_RSA_WITH_NULL_SHA256",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x003E: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
	0x003F: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0042: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0043: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0044: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
	0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
	0x0046: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0085: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x0086: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0087: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
	0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
	0x0089: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
	0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
	0x0097: "TLS_DH_DSS_WITH_SEED_CBC_SHA",
	0x0098: "TLS_DH_RSA_WITH_SEED_CBC_SHA",
	0x0099: "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
	0x009A: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
	0x009B: "TLS_DH_anon_WITH_SEED_CBC_SHA",
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00A0: "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
	0x00A1: "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
	0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
	0x00A4: "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
	0x00A5: "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
	0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
	0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
	0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
	0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
	0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
	0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
	0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
	0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
	0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
	0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
	0xC033: "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
	0xC034: "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
	0xC035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
	0xC036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
	0xC037: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
	0xC038: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
	0xC039: "TLS_ECDHE_PSK_WITH_NULL_SHA",
	0xC03A: "TLS_ECDHE_PSK_WITH_NULL_SHA256",
	0xC03B: "TLS_ECDHE_PSK_WITH_NULL_SHA384",
	0xC03C: "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
	0xC03D: "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
	0xC03E: "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
	0xC03F: "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
	0xC040: "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
	0xC041: "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
	0xC042: "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
	0xC043: "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
	0xC044: "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
	0xC045: "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
	0xC046: "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
	0xC047: "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
	0xC048: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
	0xC049: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
	0xC04A: "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
	0xC04B: "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
	0xC04C: "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
	0xC04D: "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
	0xC04E: "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
	0xC04F: "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
	0xC050: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
	0xC051: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
	0xC052: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
	0xC053: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
	0xC054: "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
	0xC055: "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
	0xC056: "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
	0xC057: "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
	0xC058: "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
	0xC059: "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
	0xC05A: "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
	0xC05B: "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
	0xC05C: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
	0xC05D: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
	0xC05E: "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
	0xC05F: "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
	0xC060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
	0xC061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
	0xC062: "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
	0xC063: "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
	0xC072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xC073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xC074: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xC075: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xC076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xC077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xC078: "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xC079: "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xC07A: "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xC07B: "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC07C: "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xC07D: "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC07E: "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xC07F: "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC080: "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
	0xC081: "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
	0xC082: "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
	0xC083: "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
	0xC084: "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
	0xC085: "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
	0xC086: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xC087: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC088: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
	0xC089: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
	0xC08A: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}

var SupportedCiphersSuite = map[uint16]int{
	0x003C: 1, // "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x009E: 2, // "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x0040: 3, // "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0xCCAA: 4, // "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x0035: 5, // "TLS_RSA_WITH_AES_256_CBC_SHA",
}

type ModCipherSuites interface {
	Name() string
	ChooseCS([]uint16) uint16
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
		for algo, preference := range SupportedCiphersSuite {
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
