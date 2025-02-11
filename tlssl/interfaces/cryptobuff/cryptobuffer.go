package cryptobuff

import (
	"crypto/x509"
	"fmt"
	"net"
	"tlesio/systema"
	ifs "tlesio/tlssl/interfaces"

	"github.com/sirupsen/logrus"
)

var (
	SERVER_HELLO        = 1 << 0
	CERTIFICATE         = 1 << 1
	SERVER_KEY_EXCHANGE = 1 << 2
	SERVER_HELLO_DONE   = 1 << 3
	CHANGE_CIPHER_SPEC  = 1 << 4
	FINISHED            = 1 << 5
)

var (
	CLIENT_HELLO        = 1 << 10
	CLIENT_KEY_EXCHANGE = 1 << 11
)

var _BuffersMap = 5 + 1

type xCryptoBuffs struct {
	clientHello       []byte
	clientKeyExchange []byte
	serverHello       []byte
	serverKeyExchange []byte
	serverHelloDone   []byte
	certificate       []byte
	finished          []byte
	cert              *x509.Certificate
}

type ifaces struct {
	header ifs.Header
}

type xCryptoBuff struct {
	ifz   ifaces
	conn  net.Conn
	lg    *logrus.Logger
	buffs *xCryptoBuffs
}

type CryptoBuff interface {
	Set(int, []byte)
	Send(int) error
	PPrint(int) string
	SetCert(*x509.Certificate)
	GetCert() *x509.Certificate
}

func NewCryptoBuff(lg *logrus.Logger, conn net.Conn) CryptoBuff {

	var newCryptoBuff xCryptoBuff

	if conn == nil || lg == nil {
		return nil
	}

	newCryptoBuff.lg = lg
	newCryptoBuff.conn = conn
	newCryptoBuff.buffs = &xCryptoBuffs{}
	newCryptoBuff.ifz.header = ifs.NewHeader()
	return &newCryptoBuff
}

func (x *xCryptoBuff) Set(op int, buff []byte) {

	if buff == nil {
		return
	}

	switch op {
	case CLIENT_HELLO:
		x.buffs.clientHello = buff
	case CLIENT_KEY_EXCHANGE:
		x.buffs.clientKeyExchange = buff
	case SERVER_HELLO:
		x.buffs.serverHello = buff
	case SERVER_KEY_EXCHANGE:
		x.buffs.serverKeyExchange = buff
	case SERVER_HELLO_DONE:
		x.buffs.serverHelloDone = buff
	case CERTIFICATE:
		x.buffs.certificate = buff
	case FINISHED:
		x.buffs.finished = buff
	}
}

func (x *xCryptoBuff) Send(op int) error {

	var outBuff []byte

	for i := 0; i < _BuffersMap; i++ {
		aux := 1 << i
		if op&aux != 0 {
			switch aux {
			case SERVER_HELLO:
				outBuff = append(outBuff, x.pts(x.buffs.serverHello)...)
				x.lg.Debug("Sending SERVER_HELLO")

			case CERTIFICATE:
				outBuff = append(outBuff, x.pts(x.buffs.certificate)...)
				x.lg.Debug("Sending CERTIFICATE")

			case SERVER_KEY_EXCHANGE:
				x.lg.Debug("Sending SERVER_KEY_EXCHANGE")

			case SERVER_HELLO_DONE:
				outBuff = append(outBuff, x.pts(x.buffs.serverHelloDone)...)
				x.lg.Debug("Sending SERVER_HELLO_DONE")

			case CHANGE_CIPHER_SPEC:
				x.lg.Debug("Sending CHANGE_CIPHER_SPEC")

			case FINISHED:
				x.lg.Debug("Sending FINISHED")
			}
		}
	}

	return x.sendData(outBuff)
}

func (x *xCryptoBuff) SetCert(cert *x509.Certificate) {
	x.buffs.cert = cert
}

func (x *xCryptoBuff) GetCert() *x509.Certificate {
	return x.buffs.cert
}

func (x *xCryptoBuff) PPrint(op int) string {

	var buff []byte

	switch op {
	case CLIENT_HELLO:
		buff = x.buffs.clientHello
	case CLIENT_KEY_EXCHANGE:
		buff = x.buffs.clientKeyExchange
	case SERVER_HELLO:
		buff = x.buffs.serverHello
	case SERVER_KEY_EXCHANGE:
		buff = x.buffs.serverKeyExchange
	case SERVER_HELLO_DONE:
		buff = x.buffs.serverHelloDone
	case CERTIFICATE:
		buff = x.buffs.certificate
	case FINISHED:
		buff = x.buffs.finished
	}

	return fmt.Sprintf("*********-  %v  -*********\n%v", len(buff),
		systema.PrettyPrintBytes(buff))
}

// Prepare buffer to be sent
func (x *xCryptoBuff) pts(buffer []byte) []byte {

	var outputBuffer []byte

	if buffer == nil {
		return nil
	}

	// Add TLS header to buffer
	outputBuffer = x.ifz.header.HeaderPacket(&ifs.TLSHeader{
		ContentType: ifs.ContentTypeHandshake,
		Version:     0x0303,
		Len:         len(buffer),
	})

	return append(outputBuffer, buffer...)
}

func (x *xCryptoBuff) sendData(buffer []byte) error {

	if buffer == nil {
		return systema.ErrNilParams
	}

	_, err := x.conn.Write(buffer)
	if err != nil {
		return err
	}

	return nil
}
