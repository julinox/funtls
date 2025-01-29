package modulos

import (
	"tlesio/systema"
)

type modulo0x00D struct {
}

type Data0x00D struct {
	Len   uint16
	Algos []uint16
}

func InitModule0x000D(config interface{}) (Modulo, error) {
	return &modulo0x00D{}, nil
}

func (e *modulo0x00D) Execute(data interface{}) interface{} {

	return nil
}

// Assuming data is in correct format
func (modulo0x00D) LoadData(data interface{}) (interface{}, error) {

	var offset uint16 = 2
	var newData Data0x00D

	mdata, ok := data.([]byte)
	if !ok {
		return nil, systema.ErrInvalidData
	}

	newData.Len = uint16(mdata[0])<<8 | uint16(mdata[1])/2
	if len(mdata) < int(newData.Len) {
		return nil, systema.ErrInvalidData
	}

	newData.Algos = make([]uint16, 0)
	for i := 0; i < int(newData.Len); i++ {
		newData.Algos = append(newData.Algos,
			uint16(mdata[offset])<<8|uint16(mdata[offset+1]))
		offset += 2
	}

	return &newData, nil
}

func (e *modulo0x00D) ID() uint16 {
	return 0x000D
}

func (e *modulo0x00D) Name() string {
	return ModuloName[e.ID()]
}

func (e *modulo0x00D) GetConfig() interface{} {
	return nil
}

func (e *modulo0x00D) Print() string {
	return "-- modulo0x00D --"
}

func (e *modulo0x00D) PrintRaw(data []byte) string {

	return "-- modulo0x00D RAW --"
}
