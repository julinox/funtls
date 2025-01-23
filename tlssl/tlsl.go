package tlssl

import (
	"tlesio/systema"
	"tlesio/tlssl/extensions"
	tx "tlesio/tlssl/extensions"

	"tlesio/tlssl/handshake"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

var _ENV_LOG_LEVEL_VAR_ = "TLS_LOG_LEVEL"

type TLS12 interface {
	HandleTLS(buffer []byte) error
}

type handShakeIface struct {
	cliHello handshake.CliHello
}

type tlsio struct {
	logg        *logrus.Logger
	handShakeIf *handShakeIface
	extns       tx.TLSExtension
}

type tlsPkt struct {
	Header       *TLSHeader
	HandShakeMsg *handshakeMsg
	Alert        *TlsAlertMsg
}

func NewTLS(lg *logrus.Logger, extns []extensions.NewExt) (TLS12, error) {

	var err error
	var ssl tlsio

	if lg == nil {
		return nil, systema.ErrNilLogger
	}

	if len(extns) <= 0 {
		ssl.logg.Error(systema.ErrNoExtensions)
		return nil, systema.ErrNoExtensions
	}

	ssl.logg = lg
	ssl.extns, err = tx.InitExtensions(lg, extns)
	if err != nil || ssl.extns == nil {
		ssl.logg.Error("Error initializing extensions2: ", err)
		return nil, err
	}

	err = initHandshakeInterface(&ssl)
	if err != nil || ssl.handShakeIf == nil {
		ssl.logg.Error("error initializing handshake interface: ", err)
		return nil, err
	}

	return &ssl, nil
}

func NewTLSDefault() (TLS12, error) {
	return NewTLS(initDefaultLogger(), initDefaultExtensions())
}

// Main TLS process function
// All errors (if no exception) should be logged here
func (tls *tlsio) HandleTLS(buffer []byte) error {

	var err error
	var packet tlsPkt
	var offset uint32 = 0

	packet.Header, err = processHeader(tls, buffer[offset:_TLSHeaderSize])
	if err != nil {
		tls.logg.Error("Error processing TLS header: ", err)
		return err
	}

	offset += _TLSHeaderSize
	switch packet.Header.ContentType {
	case ContentTypeHandshake:
		err = handleTLSHandshakeRequest(tls, buffer[offset:])
	default:
		tls.logg.Info("Unknown Header type: ", packet.Header.ContentType)
	}

	if err != nil {
		tls.logg.Error("Error processing TLS message: ", err)
	}

	return err
}

func initHandshakeInterface(tlsioo *tlsio) error {

	var newIface handShakeIface

	if tlsioo == nil {
		return systema.ErrNilController
	}

	if tlsioo.logg == nil {
		return systema.ErrNilLogger
	}

	// Default handshake interfaces never return nil
	newIface.cliHello = handshake.NewCliHello(tlsioo.logg, tlsioo.extns)
	tlsioo.handShakeIf = &newIface
	tlsioo.logg.Debug("Interface 'CliHello' initialized")
	return nil
}

func initDefaultLogger() *logrus.Logger {

	lg := clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	if lg == nil {
		return nil
	}

	lg.SetLevel(systema.GetLogLevel(_ENV_LOG_LEVEL_VAR_))
	return lg
}

func initDefaultExtensions() []tx.NewExt {

	return []tx.NewExt{
		{
			ID:     0xFFFF,
			Config: tx.Config0xFFFF{ClientWeight: 1, ServerWeight: 2},
		},
	}
}
