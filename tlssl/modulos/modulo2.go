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
	info *ModuloInfo
}

type modulador struct {
	lg    *logrus.Logger
	table map[uint16]*entry
}

var _BasicModules = []ModuloInfo{
	{Id: 0xFFFF, Fn: InitModule0xFFFF, Lg: nil},
}

func InitModulos(lg *logrus.Logger) TLSModulo2 {

	var mod modulador

	if lg == nil {
		return nil
	}

	mod.lg = lg
	mod.table = make(map[uint16]*entry)
	for _, k := range _BasicModules {
		aux, err := loadModule(&k)
		if err != nil {
			mod.lg.Error("basic module load err: ", err.Error())
			continue
		}

		mod.table[k.Id] = aux
		mod.lg.Info("basic module loaded: ", mod.table[k.Id].exec.Name())
	}

	return &mod
}

func loadModule(info *ModuloInfo) (*entry, error) {

	var err error
	var newEntry entry

	if info == nil {
		return nil, systema.ErrNilParams
	}

	newEntry.info = info
	newEntry.exec, err = info.Fn(info.Config)
	return &newEntry, err
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
