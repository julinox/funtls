package extensions

import (
	"fmt"
	"strings"

	"golang.org/x/exp/maps"
)

// The algorithm for selecting signature algorithms will use this formula:
// Score = ClientWeight ⋅ ClientPosition + ServerWeight ⋅ ServerPriority

// The weights can be adjusted through the configuration to favor one
// algorithm over another. This allows for flexible prioritization based
// on specific client and server requirements.

// Also you can force a specific algorithm using 'tax' option
var _ExtensionID uint16 = 0x000D
var supportedAlgorithms = map[uint16]int{
	0x0804: 1, // rsa_pss_rsae_sha256
	0x0401: 2, // rsa_pkcs1_sha256
	0x0805: 3, // rsa_pss_rsae_sha384
	0x0501: 4, // rsa_pkcs1_sha384
	0x0801: 5, // dsa_sha256
}

var algoNames = map[uint16]string{
	0x0804: "rsa_pss_rsae_sha256",
	0x0401: "rsa_pkcs1_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0501: "rsa_pkcs1_sha384",
	0x0801: "dsa_sha256",
}

type Extension0x00D struct {
	Config     Config0x00D
	ServerList map[uint16]int
}

type Config0x00D struct {
	ClientWeight int
	ServerWeight int
	Tax          uint16 //Force the use of a specific signature algorithm
}

func InitExtension0x000D(config interface{}) (Extension, error) {

	var extendido Extension0x00D

	if config == nil {
		config = defaultConfig()
	}

	val, ok := config.(Config0x00D)
	if !ok {
		return nil, nil
	}

	extendido.Config = val
	extendido.ServerList = make(map[uint16]int, 0)
	// Force this algorithm
	if val.Tax != 0 {
		extendido.ServerList[val.Tax] = 1

	} else {
		for algo, preference := range supportedAlgorithms {
			extendido.ServerList[algo] = preference
		}
	}

	return &extendido, nil
}

// Calculate the score for each signature algorithm and return the chosen one
// score = serverWeight*preference + clientWeight*preference
func (e *Extension0x00D) Execute(data interface{}) interface{} {

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

func (e *Extension0x00D) ID() uint16 {
	return _ExtensionID
}

func (e *Extension0x00D) Name() string {
	return extensionName[e.ID()]
}

func (e *Extension0x00D) SetConfig(cfg interface{}) bool {

	config, ok := cfg.(Config0x00D)
	if !ok {
		return false
	}

	e.Config = config
	return true
}

func (e *Extension0x00D) GetConfig() interface{} {
	return e.Config
}

// Show the supported signature algorithms
func (e *Extension0x00D) Print() string {
	return algosToName(maps.Keys(e.ServerList))
}

func defaultConfig() Config0x00D {
	return Config0x00D{
		ClientWeight: 2,
		ServerWeight: 1,
		Tax:          0,
	}
}

func algoToName(algo uint16) string {
	return fmt.Sprintf("%s(0x%04X)", algoNames[algo], algo)
}

func algosToName(algos []uint16) string {

	var names []string

	for _, v := range algos {
		names = append(names, algoToName(v))
	}

	return fmt.Sprintf("[%s]", strings.Join(names, ", "))
}
