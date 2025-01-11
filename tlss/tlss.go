package tlss

import (
	"github.com/sirupsen/logrus"
)

type tlsPkt struct {
	lg           *logrus.Logger
	header       *tlsHeader
	HandShakeMsg *tlsHandshakeMsg
	Alert        *tlsAlertMsg
	AppData      []byte
}

func TLSMe(buffer []byte, lg *logrus.Logger) error {

	var packet tlsPkt
	var offset uint32 = 0

	if lg == nil {
		return ErrNilLogger
	}

	packet.lg = lg
	if err := packet.processHeader(buffer[offset:_TLSHeaderSize]); err != nil {
		packet.lg.Error("Error processing TLS header: ", err)
		return err
	}

	offset += _TLSHeaderSize
	switch packet.header.ContentType {
	case ContentTypeHandshake:
		packet.processHandshakeMsg(buffer[offset:])
	}

	return nil
}
