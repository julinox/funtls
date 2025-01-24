package modulos

import "fmt"

// Load certificates

type modulo0xFFFE struct {
}

type Config0xFFFE struct {
}

type Data0xFFFE struct {
}

func InitExtension0xFFFE(cfg interface{}) (Modulo, error) {

	fmt.Println("Esto deberias verlo")
	return &modulo0xFFFE{}, nil
}

func (e *modulo0xFFFE) Execute(data interface{}) interface{} {

	return nil
}

func (e *modulo0xFFFE) ID() uint16 {
	return 0xFFFE
}

func (e *modulo0xFFFE) Name() string {
	return ModuloName[e.ID()]
}

func (e *modulo0xFFFE) SetConfig(cfg interface{}) bool {
	return true
}

func (e *modulo0xFFFE) GetConfig() interface{} {
	return nil
}

func (e *modulo0xFFFE) LoadData(data []byte) interface{} {
	return nil
}

func (e *modulo0xFFFE) Print() string {
	return ""
}

func (e *modulo0xFFFE) PrintRaw(data []byte) string {
	return ""
}
