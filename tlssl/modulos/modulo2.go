package modulos

import (
	"fmt"
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

type TLSModulo2 interface {
	Load(*ModuloInfo) error
}

type ModuloInfo struct {
	Id     uint16
	Fn     ModuloFn
	Config interface{}
	Lg     *logrus.Logger
}

type entry struct {
	exec Modulo
	mod  *ModuloInfo
}

type modulador struct {
	lg    *logrus.Logger
	table map[uint16]entry
}

var _BasicModules = []ModuloInfo{
	{Id: 0xFFFF, Fn: InitModule0xFFFF},
}

func InitSystem(lg *logrus.Logger) TLSModulo2 {

	var mod modulador

	if lg == nil {
		return nil
	}

	mod.lg = lg
	mod.table = make(map[uint16]entry)
	mod.loadBasicModules()
	return &mod
}

func (mod *modulador) loadBasicModules() {

	for _, k := range _BasicModules {
		mod.lg.Info("Basic modules loaded -> ", ModuloName[k.Id])
	}
}

func (mod *modulador) Load(info *ModuloInfo) error {

	if info == nil {
		return systema.ErrNilParams
	}

	if _, ok := mod.table[info.Id]; ok {
		return systema.ErrAlreadyExists
	}

	fmt.Println("REGISTRA -> ", info.Id)
	return nil
}
