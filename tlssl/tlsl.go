package tlssl

import (
	"tlesio/systema"
	mx "tlesio/tlssl/modulos"

	hx "tlesio/tlssl/handshake"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

var _ENV_LOG_LEVEL_VAR_ = "TLS_LOG_LEVEL"

type TLS12 interface {
	HandleTLS(buffer []byte) error
}

type tlsio struct {
	logg  *logrus.Logger
	mods  mx.TLSModulo
	hmods *hx.HandShake
}

type tlsPkt struct {
	Header       *TLSHeader
	HandShakeMsg *handshakeMsg
	Alert        *TlsAlertMsg
}

func NewTLS(lg *logrus.Logger) (TLS12, error) {

	var err error
	var ssl tlsio

	if lg == nil {
		return nil, systema.ErrNilLogger
	}

	ssl.logg = lg
	ssl.mods, err = mx.InitModulos(lg)
	if err != nil {
		ssl.logg.Error("error initializing extensions: ", err)
		return nil, err
	}

	ssl.hmods, err = hx.InitHandhsakeIf(lg, ssl.mods)
	if err != nil {
		ssl.logg.Error("error initializing handshake interfaces: ", err)
		return nil, err
	}

	if ssl.mods == nil || ssl.hmods == nil {
		return nil, systema.ErrNilModulo
	}

	return &ssl, nil
}

func NewTLSDefault() (TLS12, error) {
	return NewTLS(initDefaultLogger())
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
		err = newHandshakeReq(tls, buffer[offset:])
	default:
		tls.logg.Info("Unknown Header type: ", packet.Header.ContentType)
	}

	if err != nil {
		tls.logg.Error("Error processing TLS message: ", err)
	}

	return err
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
