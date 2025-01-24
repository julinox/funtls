package modulos

import (
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

type TLSModulo2 interface {
	List() []Modulo
	Get(uint16) Modulo
	Load(*ModuloInfo) error
}

type ModuloInfo struct {
	Id     uint16
	Fn     ModuloFn
	Config interface{}
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
	{Id: 0xFFFF, Fn: InitModule0xFFFF},
}

func InitModulos(lg *logrus.Logger) TLSModulo2 {

	var mod modulador

	if lg == nil {
		return nil
	}

	mod.lg = lg
	mod.table = make(map[uint16]*entry)
	for _, k := range _BasicModules {
		if err := mod.Load(&k); err != nil && err != systema.ErrAlreadyExists {
			mod.lg.Error("basic module load err: ", err.Error())
			return nil
		}

		mod.lg.Info("basic module loaded: ", mod.table[k.Id].exec.Name())
	}

	return &mod
}

func (mod *modulador) Load(info *ModuloInfo) error {

	var err error
	var newEntry entry

	if info == nil {
		return systema.ErrNilParams
	}

	if _, ok := mod.table[info.Id]; ok {
		return systema.ErrAlreadyExists
	}

	newEntry.info = info
	newEntry.exec, err = info.Fn(info.Config)
	if err != nil {
		return err
	}

	mod.table[info.Id] = &newEntry
	return nil
}

func (mod *modulador) List() []Modulo {

}
