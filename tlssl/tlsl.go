package tlssl

import (
	"fmt"
	"tlesio/systema"
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

type tlsPkt struct {
	Header       *TLSHeader
	HandShakeMsg *handshakeMsg
	Alert        *TlsAlertMsg
}

func NewTLS(lg *logrus.Logger, mods []mx.ModuloInfo) (TLS12, error) {

	var err error
	var ssl tlsio

	if lg == nil {
		return nil, systema.ErrNilLogger
	}

	ssl.logg = lg
	ssl.mods, err = mx.InitModulos(lg, mods)
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

	ssl.Close()
	return &ssl, nil
}

func (tls *tlsio) Close() {
	pp := tls.mods.Get(0xFFFE)
	if pp == nil {
		return
	}

	fmt.Printf("%v", pp.Print())
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
