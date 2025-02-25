package handshake

import (
	"crypto/x509"
	"fmt"
	"net"
	"tlesio/systema"

	//ifs "tlesio/tlssl/interfaces"

	"github.com/sirupsen/logrus"
)

var _BuffersMap = 9

type xHandhsakeContextData struct {
	certificate        []byte
	certificateRequest []byte
	changeCipherSpec   []byte
	clientHello        []byte
	clientKeyExchange  []byte
	finished           []byte
	serverHello        []byte
	serverHelloDone    []byte
	serverKeyExchange  []byte
	cert               *x509.Certificate
	cipherSuite        uint16
}

type xHandhsakeContext struct {
	coms net.Conn
	lg   *logrus.Logger
	data *xHandhsakeContextData
}

type HandShakeContext interface {
	SetCert(*x509.Certificate)
	GetCert() *x509.Certificate
	SetBuffer(int, []byte)
	GetBuffer(int) []byte
	SetCipherSuite(uint16)
	GetCipherSuite() uint16
	Send(int) error
	PPrint(int) string
}

func NewHandShakeContext(lg *logrus.Logger, conn net.Conn) HandShakeContext {

	var newContext xHandhsakeContext

	if lg == nil || conn == nil {
		return nil
	}

	newContext.lg = lg
	newContext.coms = conn
	newContext.data = &xHandhsakeContextData{}
	return &newContext
}

func (x *xHandhsakeContext) SetBuffer(op int, buff []byte) {

	if buff == nil {
		return
	}

	switch op {
	case CERTIFICATE:
		x.data.certificate = buff
	case CERTIFICATEREQUEST:
		x.data.certificateRequest = buff
	case CHANGECIPHERSPEC:
		x.data.changeCipherSpec = buff
	case CLIENTHELLO:
		x.data.clientHello = buff
	case CLIENTKEYEXCHANGE:
		x.data.clientKeyExchange = buff
	case FINISHED:
		x.data.finished = buff
	case SERVERHELLO:
		x.data.serverHello = buff
	case SERVERHELLODONE:
		x.data.serverHelloDone = buff
	case SERVERKEYEXCHANGE:
		x.data.serverKeyExchange = buff
	}
}

func (x *xHandhsakeContext) GetBuffer(op int) []byte {

	switch op {
	case CERTIFICATE:
		return x.data.certificate
	case CERTIFICATEREQUEST:
		return x.data.certificateRequest
	case CHANGECIPHERSPEC:
		return x.data.changeCipherSpec
	case CLIENTHELLO:
		return x.data.clientHello
	case CLIENTKEYEXCHANGE:
		return x.data.clientKeyExchange
	case FINISHED:
		return x.data.finished
	case SERVERHELLO:
		return x.data.serverHello
	case SERVERHELLODONE:
		return x.data.serverHelloDone
	case SERVERKEYEXCHANGE:
		return x.data.serverKeyExchange
	}

	return nil
}

func (x *xHandhsakeContext) Send(op int) error {

	var outBuff []byte

	for i := 0; i < _BuffersMap; i++ {
		aux := 1 << i
		if op&aux != 0 {
			switch aux {
			case CERTIFICATE:
				outBuff = append(outBuff, x.pts(x.data.certificate)...)
				x.lg.Debug("Sending CERTIFICATE")

			case CERTIFICATEREQUEST:
				outBuff = append(outBuff, x.pts(x.data.certificateRequest)...)
				x.lg.Debug("Sending CERTIFICATEREQUEST")

			case CHANGECIPHERSPEC:
				outBuff = append(outBuff, x.pts(x.data.changeCipherSpec)...)
				x.lg.Debug("Sending CHANGECIPHERSPEC")

			case CLIENTHELLO:
				outBuff = append(outBuff, x.pts(x.data.clientHello)...)
				x.lg.Debug("Sending CLIENTHELLO")

			case CLIENTKEYEXCHANGE:
				outBuff = append(outBuff, x.pts(x.data.clientKeyExchange)...)
				x.lg.Debug("Sending CLIENTKEYEXCHANGE")

			case FINISHED:
				outBuff = append(outBuff, x.pts(x.data.finished)...)
				x.lg.Debug("Sending FINISHED")

			case SERVERHELLO:
				outBuff = append(outBuff, x.pts(x.data.serverHello)...)
				x.lg.Debug("Sending SERVERHELLO")

			case SERVERHELLODONE:
				outBuff = append(outBuff, x.pts(x.data.serverHelloDone)...)
				x.lg.Debug("Sending SERVERHELLODONE")

			case SERVERKEYEXCHANGE:
				outBuff = append(outBuff, x.pts(x.data.serverKeyExchange)...)
				x.lg.Debug("Sending SERVERKEYEXCHANGE")
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
	case CERTIFICATE:
		buff = x.data.certificate

	case CERTIFICATEREQUEST:
		buff = x.data.certificateRequest

	case CHANGECIPHERSPEC:
		buff = x.data.changeCipherSpec

	case CLIENTHELLO:
		buff = x.data.clientHello

	case CLIENTKEYEXCHANGE:
		buff = x.data.clientKeyExchange

	case SERVERHELLO:
		buff = x.data.serverHello

	case FINISHED:
		buff = x.data.finished

	case SERVERHELLODONE:
		buff = x.data.serverHelloDone

	case SERVERKEYEXCHANGE:
		buff = x.data.serverKeyExchange
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
	/*outputBuffer = x.ifz.header.HeaderPacket(&ifs.TLSHeader{
		ContentType: ifs.ContentTypeHandshake,
		Version:     0x0303,
		Len:         len(buffer),
	})*/

	return append(outputBuffer, buffer...)
}

func (x *xHandhsakeContext) sendData(buffer []byte) error {

	if buffer == nil {
		return systema.ErrNilParams
	}

	_, err := x.coms.Write(buffer)
	if err != nil {
		return err
	}

	return nil
}
