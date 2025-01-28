package modulos

import (
	"golang.org/x/exp/maps"
)

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

	return &extendido, nil
}

// Calculate the score for each signature algorithm and return the chosen one
// score = serverWeight*preference + clientWeight*preference
func (e *modulo0x00D) Execute(data interface{}) interface{} {

	return nil
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
