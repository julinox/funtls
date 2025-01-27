package modulos

import (
	syst "tlesio/systema"

	"github.com/sirupsen/logrus"
)

// The idea of this module is to handle extensions or 'features' in a more
// dynamic way, like a module (enabling/disabling, reload, change config, etc)

var ModuloName = map[uint16]string{
	// extensions
	0x0000: "server_name",
	0x0001: "max_fragment_length",
	0x0002: "client_certificate_url",
	0x0003: "trusted_ca_keys",
	0x0004: "truncated_hmac",
	0x0005: "status_request",
	0x0006: "user_mapping",
	0x0007: "client_authz",
	0x0008: "server_authz",
	0x0009: "cert_type",
	0x000A: "supported_groups",
	0x000B: "ec_point_formats",
	0x000C: "srp",
	0x000D: "signature_algorithms",
	0x000E: "use_srtp",
	0x000F: "heartbeat",
	0x0010: "application_layer_protocol_negotiation",
	0x0011: "status_request_v2",
	0x0012: "signed_certificate_timestamp",
	0x0013: "client_certificate_type",
	0x0014: "server_certificate_type",
	0x0015: "padding",
	0x0016: "encrypt_then_mac",
	0x0017: "extended_master_secret",
	0x0018: "token_binding",
	0x0019: "cached_info",
	0x0023: "session_ticket",

	// not extensions
	0xfffe: "certificate_load",
	0xffff: "cipher_suite",
}

type ModuloFn func(interface{}) (Modulo, error)
type Modulo interface {
	ID() uint16
	Name() string
	Print() string
	PrintRaw(data []byte) string
	SetConfig(interface{}) bool
	GetConfig() interface{}
	LoadData([]byte) interface{}
	Execute(interface{}) interface{}
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
