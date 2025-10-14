package extensions

import (
	"github.com/sirupsen/logrus"
)

var ExtensionName = map[uint16]string{
	0x0000: "server_name",
	0x000A: "supported_groups",
	0x000D: "signature_algorithms",
	0x0016: "encrypt_then_mac",
	0x0023: "session_ticket",
	0xFF01: "renegotiation_info",
}

const (
	EXT_SERVER_NAME          = 0x0000
	EXT_SUPPORTED_GROUPS     = 0x000A
	EXT_SIGNATURE_ALGORITHMS = 0x000D
	EXT_ENCRYPT_THEN_MAC     = 0x0016
	EXT_SESSION_TICKET       = 0x0023
	EXT_RENEGOTIATION_INFO   = 0xFF01
)

type ExtLoadFN func([]byte, int) (interface{}, error)

type Extension interface {
	ID() uint16
	Name() string
	PrintRaw([]byte) string
	PacketServerHelo(any) ([]byte, error)
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
