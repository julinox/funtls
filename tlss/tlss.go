package tlss

import (
	"tlesio/systema"
	"tlesio/tlss/extensions"

	"github.com/sirupsen/logrus"
)

type TLSControl interface {
	SetLogger(*logrus.Logger)
	SetExtensions(extensions.TLSExtension)
}

type controller struct {
	lg   *logrus.Logger
	exts extensions.TLSExtension
}

type tlsPkt struct {
	Header       *TlsHeader
	HandShakeMsg *TlsHandshakeMsg
	Alert        *TlsAlertMsg
	lg           *logrus.Logger
}

func NewTlsController() TLSControl {

	return &controller{}
}

func (ctrl *controller) SetLogger(lg *logrus.Logger) {
	ctrl.lg = lg
}

func (ctrl *controller) SetExtensions(exts extensions.TLSExtension) {
	ctrl.exts = exts
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
