package tlss

import (
	"tlesio/systema"
	"tlesio/tlss/extensions"
	tx "tlesio/tlss/extensions"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

type TLS12 interface {
	HandleTLS(buffer []byte) error
}

type tlsio struct {
	//extns []uint16 ?
	logg  *logrus.Logger
	extns tx.TLSExtension
}

type tlsPkt struct {
	Header       *TlsHeader
	HandShakeMsg *TlsHandshakeMsg
	Alert        *TlsAlertMsg
	lg           *logrus.Logger
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
	if err != nil {
		ssl.logg.Error("Error initializing extensions: ", err)
		return nil, err
	}

	return &ssl, nil
}

func NewTLSDefault() (TLS12, error) {
	return NewTLS(defaultLogger(), defaultExtensions())
}

func (tls *tlsio) HandleTLS(buffer []byte) error {
	return nil
}

func defaultLogger() *logrus.Logger {

	lg := clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	if lg == nil {
		return nil
	}

	lg.SetLevel(logrus.InfoLevel)
	return lg
}

func defaultExtensions() []tx.NewExt {

	return []tx.NewExt{
		tx.NewExt{
			ID:     0x000D,
			Config: tx.Config0x00D{ClientWeight: 1, ServerWeight: 2},
		},
	}
}

func TLSMe(buffer []byte, lg *logrus.Logger) error {

	var packet tlsPkt
	var offset uint32 = 0

	if lg == nil {
		return systema.ErrNilLogger
	}

	packet.lg = lg
	if err := packet.processHeader(buffer[offset:_TLSHeaderSize]); err != nil {
		packet.lg.Error("Error processing TLS header: ", err)
		return err
	}

	offset += _TLSHeaderSize
	switch packet.Header.ContentType {
	case ContentTypeHandshake:
		packet.processHandshakeMsg(buffer[offset:])
	}

	return nil
}
