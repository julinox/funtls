package modulos

import (
	"fmt"
	syst "tlesio/systema"

	"github.com/sirupsen/logrus"
)

var ModuloName = map[uint16]string{
	0x000D: "signature_algorithms",
	0xfffe: "certificate_load",
	0xffff: "cipher_suite",
}

type ModuloFn func(interface{}) (Modulo, error)
type Modulo interface {
	ID() uint16
	Name() string
	Print() string
	PrintRaw(data []byte) string
	GetConfig() interface{}
	Execute(interface{}) interface{}
	LoadData(interface{}) (interface{}, error)
}

type TLSModulo interface {
	List() []Modulo
	Get(uint16) Modulo
	Unload(uint16) error
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

func InitModulos(lg *logrus.Logger, mods []ModuloInfo) (TLSModulo, error) {
	//func InitModulos(lg *logrus.Logger) (TLSModulo, error) {

	var mod modulador

	if lg == nil {
		return nil, syst.ErrNilLogger
	}

	if len(mods) <= 0 {
		return nil, syst.ErrNilModulo
	}

	mod.lg = lg
	mod.table = make(map[uint16]*entry)
	for _, k := range mods {
		if err := mod.Load(&k); err != nil && err != syst.ErrAlreadyExists {
			return nil, err
		}

		mod.lg.Info("Module loaded: ", mod.table[k.Id].exec.Name())
	}

	return &mod, nil
}

func (mod *modulador) Load(info *ModuloInfo) error {

	var err error
	var newEntry entry

	if info == nil {
		return syst.ErrNilParams
	}

	if _, ok := mod.table[info.Id]; ok {
		return syst.ErrAlreadyExists
	}

	newEntry.info = info
	newEntry.exec, err = info.Fn(info.Config)
	if err != nil {
		return err
	}

	mod.table[info.Id] = &newEntry
	return nil
}

func (mod *modulador) Unload(id uint16) error {

	if _, ok := mod.table[id]; ok {
		delete(mod.table, id)
		mod.lg.Info("module unloaded: ", ModuloName[id])
		return nil
	}

	return syst.ErrNotFound
}

func (mod *modulador) List() []Modulo {

	var mm []Modulo

	for _, k := range mod.table {
		mm = append(mm, k.exec)
	}

	return mm
}

func (mod *modulador) Get(id uint16) Modulo {

	if _, ok := mod.table[id]; ok {
		return mod.table[id].exec
	}

	return nil
}

func ReturnErr(moduloName, msg string) error {
	return fmt.Errorf("%v: %v", moduloName, msg)
}
