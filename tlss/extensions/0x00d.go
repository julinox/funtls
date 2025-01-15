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

type priority struct {
	hexCode uint16
	peer    int
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
	// Force the use of a specific signature algorithm
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
// Since A ⊆ B, A ∩ B = List of matching algorithms (where A is the smallest
// list between client and server)
func (e *Extension0x00D) Execute(data interface{}) interface{} {

	clientList, ok := data.(map[uint16]int)
	if !ok {
		return nil
	}

	if len(clientList) == 0 || len(e.ServerList) == 0 {
		return nil
	}

	if len(clientList) < len(e.ServerList) {
		helper1(e.ServerList, clientList,
			e.Config.ServerWeight, e.Config.ClientWeight)
	} else {
		helper1(clientList, e.ServerList,
			e.Config.ClientWeight, e.Config.ServerWeight)
	}

	//table = make([]priority, 0)
	/*for _, cHexCode := range dt {
		if e.ServerList[cHexCode] == 0 {
			continue
		}

		//fmt.Printf("%v\n", algoToName(cHexCode))
		//table = append(table, priority{cHexCode, })
		//table = append(table, priority{cHexCode, cPreference, e.ServerList[cHexCode]})

		//fmt.Printf("%x(%v) | %v | %v\n", cHexCode, algoToName(cHexCode),
		//table[counter].client, table[counter].server)
	}*/

	return 0
}

func helper1(it, fixed map[uint16]int, itW, fixedW int) {

	// var table []priority
	for algo, _ := range it {
		fmt.Printf("%v ?? %v\n", algoToName(algo), fixed[algo])
	}
}

/*
//f1 := formula1(e.Config.ClientWeight, v,e.Config.ServerWeight, e.ServerList[k])
			//f1 := formula1(e.Config.ClientWeight, v, e.Config.ServerWeight, e.ServerList[k])
			//fmt.Printf("aux(%v) = %v | ", algoToName(k), f1)
			//fmt.Printf("%v * %v + %v * %v\n", e.Config.ClientWeight, v, e.Config.ServerWeight, e.ServerList[k])
			if uint16(aux) < current {
				fmt.Println("ganando -> ", algoToName(k))
				current = uint16(aux)
			}
*/

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
	return algosToName(maps.Keys(e.ServerList))
}

func formula1(cw, cp, sw, sp int) int {
	return cw*cp + sw*sp
}

func formula2(cw, cp, sw, sp int) float32 {
	return float32(cw)*(float32(1/cp)) + float32(sw)*(float32(1/sp))
}

func defaultConfig() Config0x00D {
	return Config0x00D{
		ClientWeight: 1,
		ServerWeight: 2,
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
