package tlssl

import (
	mx "tlesio/tlssl/modulos"

	hx "tlesio/tlssl/handshake"

	"github.com/sirupsen/logrus"
)

type TLS12 interface {
	HandleTLS(buffer []byte) error
}

type tlsio struct {
	logg  *logrus.Logger
	mods  mx.TLSModulo
	hmods *hx.HandShake
}

/*type tlsPkt struct {
	Header       *TLSHeader
	HandShakeMsg *handshakeMsg
	Alert        *TlsAlertMsg
}*/

// Main TLS process function
// All errors (if no exception) should be logged here
func (tls *tlsio) HandleTLS(buffer []byte) error {

	/*var err error
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

	return err*/
	return nil
}
