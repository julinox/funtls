package extensions

import (
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

// The idea of this module is to handle extensions in a more dynamic way,
// like a module (enabling/disabling extensions, reload, change config, etc)

/*
	vas a cargar la extension de signalgo, necesita un config
	luego vas a desactivarla y luego cambiar config
*/

var extensionName = map[uint16]string{
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
}

var defaultExtensions = []NewExt{
	{0x000D, nil}, // signature_algorithms
}

type Extension interface {
	ID() uint16
	Name() string
	Print() string // Print whatever you want to show from the extension
	SetConfig(interface{})
	GetConfig() interface{}
	Execute(interface{}) interface{}
}

type TlsExtension interface {
	//Get()
	List() []Extension
	Enable()
	Disable()
}

type NewExt struct {
	ID     uint16
	Config interface{}
}

type HelloKitty struct {
	extensions []Extension
	lg         *logrus.Logger
}

func InitExtensions(lg *logrus.Logger, exts []NewExt) (TlsExtension, error) {

	var hky HelloKitty

	if lg == nil {
		return nil, systema.ErrNilLogger
	}

	if len(exts) <= 0 {
		exts = defaultExtensions
	}

	hky.lg = lg
	hky.extensions = make([]Extension, 0)
	for _, k := range exts {
		switch k.ID {
		case 0x000D:
			ext, err := InitExtension0x000D(k.Config)
			if err != nil {
				lg.Error("Error initializing extension 0x000D: ", err)
				continue
			}

			lg.Infof("Extension '%v'(0x000D) initialized", ext.Name())
			lg.Debugf("Extension '%v'(0x000D) Print() -> %v", ext.Name(), ext.Print())
			hky.extensions = append(hky.extensions, ext)
		}
	}

	return &hky, nil
}

func (hk *HelloKitty) List() []Extension {

	return hk.extensions
}

func (hk *HelloKitty) Enable() {

}

func (hk *HelloKitty) Disable() {

}
