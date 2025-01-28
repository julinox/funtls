package modulos

import (
	"fmt"
	"tlesio/systema"

	"golang.org/x/exp/maps"
)

var _SignatureHashAlgorithms = map[uint16]string{
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0303: "ecdsa_sha224",
	0x0301: "rsa_sha224",
	0x0302: "dsa_sha224",
	0x0402: "dsa_sha256",
	0x0502: "dsa_sha384",
	0x0602: "dsa_sha512",
}

var _SupportedAlgorithms = map[uint16]int{
	0x0804: 1, // rsa_pss_rsae_sha256
	0x0401: 2, // rsa_pkcs1_sha256
	0x0805: 3, // rsa_pss_rsae_sha384
	0x0501: 4, // rsa_pkcs1_sha384
	0x0402: 5, // dsa_sha256
}

type modulo0x00D struct {
	Config     Config0x00D
	ServerList map[uint16]int
}

type Config0x00D struct {
	ClientWeight int
	ServerWeight int
	Tax          uint16 //Force the use of a specific signature algorithm
}

type Data0x00D struct {
	Len   uint16
	Algos []uint16
}

func InitModule0x000D(config interface{}) (Modulo, error) {

	var extendido modulo0x00D

	if config == nil {
		config = defaultConfig()
	}

	val, ok := config.(Config0x00D)
	if !ok {
		return nil, fmt.Errorf("%v (%v)", systema.ErrInvalidConfig, "Modulo 0x000D")
	}

	extendido.Config = val
	extendido.ServerList = make(map[uint16]int, 0)
	// Force this algorithm
	if val.Tax != 0 {
		extendido.ServerList[val.Tax] = 1

	} else {
		for algo, preference := range _SupportedAlgorithms {
			extendido.ServerList[algo] = preference
		}
	}

	return &extendido, nil
}

// Calculate the score for each signature algorithm and return the chosen one
// score = serverWeight*preference + clientWeight*preference
func (e *modulo0x00D) Execute(data interface{}) interface{} {

	var lighter int
	var chosen uint16

	clientList, ok := data.([]uint16)
	if !ok {
		return nil
	}

	if len(e.ServerList) == 0 || len(clientList) == 0 {
		return nil
	}

	count := 1
	lighter = 1 << 16
	chosen = 0
	for _, a := range clientList {
		if e.ServerList[a] == 0 {
			continue
		}

		aux := (e.Config.ServerWeight * e.ServerList[a]) +
			(e.Config.ClientWeight * count)
		if aux < lighter {
			lighter = aux
			chosen = a
		}

		count++
	}

	return chosen
}

// Assuming data is in correct format
func (modulo0x00D) LoadData(data interface{}) (interface{}, error) {
	return nil, nil
}

func (e *modulo0x00D) ID() uint16 {
	return 0x000D
}

func (e *modulo0x00D) Name() string {
	return ModuloName[e.ID()]
}

func (e *modulo0x00D) GetConfig() interface{} {
	return e.Config
}

// Show the supported signature algorithms
func (e *modulo0x00D) Print() string {
	return AlgosToName(e.ID(), maps.Keys(e.ServerList))
}

func (e *modulo0x00D) PrintRaw(data []byte) string {

	var str string
	var offset uint16 = 2

	len := uint16(data[0])<<8 | uint16(data[1])/2
	for i := 0; i < int(len); i++ {
		str += "\n" + AlgoToName(e.ID(),
			uint16(data[offset])<<8|uint16(data[offset+1]))
		offset += 2
	}

	return str
}

func defaultConfig() Config0x00D {
	return Config0x00D{
		ClientWeight: 2,
		ServerWeight: 1,
		Tax:          0,
	}
}
