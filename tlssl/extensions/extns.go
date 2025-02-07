package extensions

import (
	"github.com/sirupsen/logrus"
)

var ExtensionName = map[uint16]string{
	0x000D: "signature_algorithms",
}

type ExtLoadFN func([]byte, int) (interface{}, error)

type Extension interface {
	ID() uint16
	Name() string
	PrintRaw([]byte) string
	PacketServerHelo() []byte
	LoadData([]byte, int) (interface{}, error)
}

type Extensions struct {
	lg    *logrus.Logger
	table map[uint16]Extension
}

func NewExtensions(lg *logrus.Logger) *Extensions {

	var newExtns Extensions

	newExtns.lg = lg
	newExtns.table = make(map[uint16]Extension)
	return &newExtns
}

func (e *Extensions) Register(ext Extension) {

	if ext == nil {
		return
	}

	if _, ok := e.table[ext.ID()]; ok {
		e.lg.Warn("Extension already registered: ", ext.Name())
	}

	e.table[ext.ID()] = ext
	e.lg.Info("Extension registered: ", ext.Name())
}

func (e *Extensions) Get(id uint16) Extension {

	if ext, ok := e.table[id]; ok {
		return ext
	}

	return nil
}

func (e Extensions) GetAll() map[uint16]Extension {
	return e.table
}
