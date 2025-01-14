package extensions

import (
	"fmt"
	"strings"
)

// The algorithm for selecting signature algorithms will use this formula:
// Score = ClientWeight ⋅ ClientPosition + ServerWeight ⋅ ServerPriority

// The weights can be adjusted through the configuration to favor one
// algorithm over another. This allows for flexible prioritization based
// on specific client and server requirements.

var signAlgoSupported = map[uint16]int{
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
	extendido.ServerList = make(map[uint16]int)
	// Force the use of a specific signature algorithm
	if val.Tax != 0 {
		extendido.ServerList[val.Tax] = 1

	} else {
		for k, v := range signAlgoSupported {
			extendido.ServerList[k] = v
		}
	}

	return &extendido, nil
}

// Calculate the score for each signature algorithm and return the highest
func (e *Extension0x00D) Execute(data interface{}) interface{} {

	var current uint16

	current = 1 << 15
	dt, ok := data.(map[uint16]int)
	if !ok {
		return nil
	}

	for k, v := range dt {
		if ok := e.ServerList[k]; ok != 0 {
			aux := e.Config.ClientWeight*v + e.Config.ServerWeight*e.ServerList[k]
			fmt.Printf("aux(%v) = %v | Current = %v\n", algoToName(k), aux, current)
			if uint16(aux) < current {
				fmt.Println("ganando -> ", algoToName(k))
				current = uint16(aux)
			}

		}

	}

	//fmt.Println(e.ServerList)
	return 0
}

func (e *Extension0x00D) ID() uint16 {
	return 0x000D
}

func (e *Extension0x00D) Name() string {
	return extensionName[e.ID()]
}

func (e *Extension0x00D) SetConfig(cfg interface{}) {
	//e.cfg = cfg
	fmt.Println("Loteria??")
}

func (e *Extension0x00D) GetConfig() interface{} {
	return e.Config
}

// Show the selected signature algorithms
func (e *Extension0x00D) Print() string {

	return algosToName(e.ServerList)
}

func defaultConfig() Config0x00D {
	return Config0x00D{
		ClientWeight: 1,
		ServerWeight: 2,
		Tax:          0,
	}
}

func algosToName(algos map[uint16]int) string {

	var names []string

	for k := range algos {
		names = append(names, fmt.Sprintf("%s(0x%04X)", algoNames[k], k))
	}

	return fmt.Sprintf("[%s]", strings.Join(names, ", "))
}

func algoToName(algo uint16) string {
	return fmt.Sprintf("%s(0x%04X)", algoNames[algo], algo)
}
