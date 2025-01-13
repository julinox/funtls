package extensions

import "fmt"

// The algorithm for selecting signature algorithms will use this formula:
// Score = ClientWeight ⋅ ClientPosition + ServerWeight ⋅ ServerPriority

// The weights can be adjusted through the configuration to favor one
// algorithm over another. This allows for flexible prioritization based
// on specific client and server requirements.

var signAlgoSupported = map[uint16]int{
	0x0401: 1, // rsa_pss_rsae_sha256
	0x0501: 2, // rsa_pkcs1_sha256
	0x0601: 3, // rsa_pss_rsae_sha384
	0x0701: 4, // rsa_pkcs1_sha384
	0x0801: 5, // dsa_sha256
}

var algoNames = map[uint16]string{
	0x0401: "rsa_pss_rsae_sha256",
	0x0501: "rsa_pkcs1_sha256",
	0x0601: "rsa_pss_rsae_sha384",
	0x0701: "rsa_pkcs1_sha384",
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

	fmt.Println("DEBUGO1")
	fmt.Println(algosToName(extendido.ServerList))
	fmt.Println("DEBUGO2")
	return &extendido, nil
}

func (e *Extension0x00D) ID() uint16 {
	return 0x000D
}

func (e *Extension0x00D) Name() string {
	return extensionName[e.ID()]
}

func (e *Extension0x00D) SetConfig(cfg interface{}) {
	//e.cfg = cfg
}

func (cfg *Config0x00D) Weight() {

}

func defaultConfig() Config0x00D {
	return Config0x00D{
		ClientWeight: 1,
		ServerWeight: 2,
		Tax:          0,
	}
}

func algosToName(algos map[uint16]int) string {

	var name string

	count := 0
	total := len(algos)
	for k := range algos {
		name += fmt.Sprintf("%v(%x)", algoNames[k], k)
		count++
		if count < total {
			name += "\n"
		}
	}

	return name
}
