package interfaces

import (
	"crypto/x509"
	"fmt"
	"net"
	"tlesio/systema"

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

type xHandhsakeContextData struct {
	clientHello       []byte
	clientKeyExchange []byte
	serverHello       []byte
	serverKeyExchange []byte
	serverHelloDone   []byte
	certificate       []byte
	finished          []byte
	cert              *x509.Certificate
	cipherSuite       uint16
}

type ifaces struct {
	header Header
}

type xHandhsakeContext struct {
	ifz  ifaces
	conn net.Conn
	lg   *logrus.Logger
	data *xHandhsakeContextData
}

type HandShakeContext interface {
	SetBuffer(int, []byte)
	Send(int) error
	PPrint(int) string
	SetCipherSuite(uint16)
	GetCipherSuite() uint16
	SetCert(*x509.Certificate)
	GetCert() *x509.Certificate
	GetBuffer(int) []byte
}

func NewHandShakeContext(lg *logrus.Logger, conn net.Conn) HandShakeContext {

	var newContext xHandhsakeContext

	if conn == nil || lg == nil {
		return nil
	}

	newContext.lg = lg
	newContext.conn = conn
	newContext.data = &xHandhsakeContextData{}
	newContext.ifz.header = NewHeader()
	return &newContext
}

func (x *xHandhsakeContext) SetBuffer(op int, buff []byte) {

	if buff == nil {
		return
	}

	switch op {
	case CLIENT_HELLO:
		x.data.clientHello = buff
	case CLIENT_KEY_EXCHANGE:
		x.data.clientKeyExchange = buff
	case SERVER_HELLO:
		x.data.serverHello = buff
	case SERVER_KEY_EXCHANGE:
		x.data.serverKeyExchange = buff
	case SERVER_HELLO_DONE:
		x.data.serverHelloDone = buff
	case CERTIFICATE:
		x.data.certificate = buff
	case FINISHED:
		x.data.finished = buff
	}
}

func (x *xHandhsakeContext) GetBuffer(op int) []byte {

	switch op {
	case CLIENT_HELLO:
		return x.data.clientHello
	case CLIENT_KEY_EXCHANGE:
		return x.data.clientKeyExchange
	case SERVER_HELLO:
		return x.data.serverHello
	case SERVER_KEY_EXCHANGE:
		return x.data.serverKeyExchange
	case SERVER_HELLO_DONE:
		return x.data.serverHelloDone
	case CERTIFICATE:
		return x.data.certificate
	case FINISHED:
		return x.data.finished
	}

	return nil
}

func (x *xHandhsakeContext) Send(op int) error {

	var outBuff []byte

	for i := 0; i < _BuffersMap; i++ {
		aux := 1 << i
		if op&aux != 0 {
			switch aux {
			case SERVER_HELLO:
				outBuff = append(outBuff, x.pts(x.data.serverHello)...)
				x.lg.Debug("Sending SERVER_HELLO")

			case CERTIFICATE:
				outBuff = append(outBuff, x.pts(x.data.certificate)...)
				x.lg.Debug("Sending CERTIFICATE")

			case SERVER_KEY_EXCHANGE:
				x.lg.Debug("Sending SERVER_KEY_EXCHANGE")

			case SERVER_HELLO_DONE:
				outBuff = append(outBuff, x.pts(x.data.serverHelloDone)...)
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

func (x *xHandhsakeContext) SetCert(cert *x509.Certificate) {
	x.data.cert = cert
}

func (x *xHandhsakeContext) GetCert() *x509.Certificate {
	return x.data.cert
}

func (x *xHandhsakeContext) SetCipherSuite(cipherSuite uint16) {
	x.data.cipherSuite = cipherSuite
}

func (x *xHandhsakeContext) GetCipherSuite() uint16 {
	return x.data.cipherSuite
}

func (x *xHandhsakeContext) PPrint(op int) string {

	var buff []byte

	switch op {
	case CLIENT_HELLO:
		buff = x.data.clientHello
	case CLIENT_KEY_EXCHANGE:
		buff = x.data.clientKeyExchange
	case SERVER_HELLO:
		buff = x.data.serverHello
	case SERVER_KEY_EXCHANGE:
		buff = x.data.serverKeyExchange
	case SERVER_HELLO_DONE:
		buff = x.data.serverHelloDone
	case CERTIFICATE:
		buff = x.data.certificate
	case FINISHED:
		buff = x.data.finished
	}

	return fmt.Sprintf("*********-  %v  -*********\n%v", len(buff),
		systema.PrettyPrintBytes(buff))
}

// Prepare buffer to be sent
func (x *xHandhsakeContext) pts(buffer []byte) []byte {

	var outputBuffer []byte

	if buffer == nil {
		return nil
	}

	// Add TLS header to buffer
	outputBuffer = x.ifz.header.HeaderPacket(&TLSHeader{
		ContentType: ContentTypeHandshake,
		Version:     0x0303,
		Len:         len(buffer),
	})

	return append(outputBuffer, buffer...)
}

func (x *xHandhsakeContext) sendData(buffer []byte) error {

	if buffer == nil {
		return systema.ErrNilParams
	}

	_, err := x.conn.Write(buffer)
	if err != nil {
		return err
	}

	return nil
}
