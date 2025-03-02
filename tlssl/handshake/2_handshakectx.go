package handshake

import (
	"crypto/x509"
	"fmt"
	"net"
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

const (
	CLIENTCERTIFICATE = 3
	SERVERCERTIFICATE = 7
)

type xHandhsakeContextData struct {
	certificate        []byte
	certificateRequest []byte
	certificateverify  []byte
	changeCipherSpec   []byte
	clientCertificate  []byte
	clientHello        []byte
	clientKeyExchange  []byte
	finished           []byte
	serverHello        []byte
	serverHelloDone    []byte
	serverKeyExchange  []byte
	serverCert         *x509.Certificate
	msgHello           *MsgHello
	cipherSuite        uint16
	transitionStage    int
	order              []int
	expected           int
}

type xHandhsakeContext struct {
	coms net.Conn
	lg   *logrus.Logger
	data *xHandhsakeContextData
}

type HandShakeContext interface {
	SetBuffer(int, []byte)
	GetBuffer(int) []byte
	SetCert(*x509.Certificate)
	GetCert() *x509.Certificate
	SetMsgHello(*MsgHello)
	GetMsgHello() *MsgHello
	SetCipherSuite(uint16)
	GetCipherSuite() uint16
	SetTransitionStage(int)
	GetTransitionStage() int
	Order() []int
	AppendOrder(int) error
	PrintOrder() string
	Expected() int
	FlagExpected(int)
	UnflagExpected(int)
	PrintExpected() string
	Send([]int) error
	PPrint(int) string
}

func NewHandShakeContext(lg *logrus.Logger, coms net.Conn) HandShakeContext {

	var newContext xHandhsakeContext

	if lg == nil || coms == nil {
		return nil
	}

	newContext.lg = lg
	newContext.coms = coms
	newContext.data = &xHandhsakeContextData{}
	newContext.data.expected |= CLIENTKEYEXCHANGE
	newContext.data.expected |= CHANGECIPHERSPEC
	newContext.data.expected |= FINISHED
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

	case CERTIFICATEVERIFY:
		x.data.certificateverify = buff

	case CHANGECIPHERSPEC:
		x.data.changeCipherSpec = buff

	case CLIENTCERTIFICATE:
		x.data.clientCertificate = buff

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

	case CERTIFICATEVERIFY:
		return x.data.certificateverify

	case CHANGECIPHERSPEC:
		return x.data.changeCipherSpec

	case CLIENTCERTIFICATE:
		return x.data.clientCertificate

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

func (x *xHandhsakeContext) SetCert(cert *x509.Certificate) {
	x.data.serverCert = cert
}

func (x *xHandhsakeContext) GetCert() *x509.Certificate {
	return x.data.serverCert
}

func (x *xHandhsakeContext) SetMsgHello(msg *MsgHello) {
	x.data.msgHello = msg
}

func (x *xHandhsakeContext) GetMsgHello() *MsgHello {
	return x.data.msgHello
}

func (x *xHandhsakeContext) SetCipherSuite(cipherSuite uint16) {
	x.data.cipherSuite = cipherSuite
}

func (x *xHandhsakeContext) GetCipherSuite() uint16 {
	return x.data.cipherSuite
}

func (x *xHandhsakeContext) SetTransitionStage(stage int) {
	x.data.transitionStage = stage
}

func (x *xHandhsakeContext) GetTransitionStage() int {
	return x.data.transitionStage
}

func (x *xHandhsakeContext) Order() []int {
	return x.data.order
}

func (x *xHandhsakeContext) AppendOrder(op int) error {

	switch op {
	case CERTIFICATE:
		fallthrough
	case CERTIFICATEREQUEST:
		fallthrough
	case CERTIFICATEVERIFY:
		fallthrough
	case CHANGECIPHERSPEC:
		fallthrough
	case CLIENTHELLO:
		fallthrough
	case CLIENTKEYEXCHANGE:
		fallthrough
	case FINISHED:
		fallthrough
	case SERVERHELLO:
		fallthrough
	case SERVERHELLODONE:
		fallthrough
	case SERVERKEYEXCHANGE:
		break
	default:
		return fmt.Errorf("invalid order append operation")
	}

	x.data.order = append(x.data.order, op)
	return nil
}

func (x *xHandhsakeContext) PrintOrder() string {
	return _X_(x.data.order)
}

// All posible handshake messages from client
// CERTIFICATE, CLIENTKEYEXCHANGE, CERTIFICATEVERIFY,
// CHANGECIPHERSPEC, FINISHED
func (x *xHandhsakeContext) Expected() int {
	return x.data.expected
}

func (x *xHandhsakeContext) FlagExpected(op int) {

	switch op {
	case CERTIFICATE:
		fallthrough
	case CLIENTKEYEXCHANGE:
		fallthrough
	case CERTIFICATEVERIFY:
		fallthrough
	case CHANGECIPHERSPEC:
		fallthrough
	case FINISHED:
		break
	default:
		return
	}

	x.data.expected |= op
}

func (x *xHandhsakeContext) UnflagExpected(op int) {

	switch op {
	case CERTIFICATE:
		fallthrough
	case CLIENTKEYEXCHANGE:
		fallthrough
	case CERTIFICATEVERIFY:
		fallthrough
	case CHANGECIPHERSPEC:
		fallthrough
	case FINISHED:
		break
	default:
		return
	}

	x.data.expected &= ^op
}

func (x *xHandhsakeContext) PrintExpected() string {

	var expected []int

	allExpected := []int{
		CERTIFICATE,
		CLIENTKEYEXCHANGE,
		CERTIFICATEVERIFY,
		CHANGECIPHERSPEC,
		FINISHED,
	}

	for _, v := range allExpected {
		if x.data.expected&v != 0 {
			expected = append(expected, v)
		}
	}

	return _X_(expected)
}

func (x *xHandhsakeContext) Send(ids []int) error {

	var outBuff []byte

	for _, id := range ids {
		switch id {
		case CERTIFICATE:
			outBuff = append(outBuff, x.data.certificate...)
			x.lg.Debug("Sending CERTIFICATE")

		case CERTIFICATEREQUEST:
			outBuff = append(outBuff, x.data.certificateRequest...)
			x.lg.Debug("Sending CERTIFICATEREQUEST")

		case CERTIFICATEVERIFY:
			outBuff = append(outBuff, x.data.certificateverify...)
			x.lg.Debug("Sending CERTIFICATEVERIFY")

		case CHANGECIPHERSPEC:
			outBuff = append(outBuff, x.data.changeCipherSpec...)
			x.lg.Debug("Sending CHANGECIPHERSPEC")

		case CLIENTHELLO:
			x.lg.Warn("What do you mean by 'Send ClientHello'?")

		case CLIENTKEYEXCHANGE:
			outBuff = append(outBuff, x.data.clientKeyExchange...)
			x.lg.Debug("Sending CLIENTKEYEXCHANGE")

		case FINISHED:
			outBuff = append(outBuff, x.data.finished...)
			x.lg.Debug("Sending FINISHED")

		case SERVERHELLO:
			outBuff = append(outBuff, x.data.serverHello...)
			x.lg.Debug("Sending SERVERHELLO")

		case SERVERHELLODONE:
			outBuff = append(outBuff, x.data.serverHelloDone...)
			x.lg.Debug("Sending SERVERHELLODONE")

		case SERVERKEYEXCHANGE:
			outBuff = append(outBuff, x.data.serverKeyExchange...)
			x.lg.Debug("Sending SERVERKEYEXCHANGE")
		}
	}

	return x.sendData(outBuff)
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

func _X_(l []int) string {

	out := "["

	for i, v := range l {
		switch v {
		case CERTIFICATE:
			out += "CERTIFICATE"

		case CERTIFICATEREQUEST:
			out += "CERTIFICATEREQUEST"

		case CERTIFICATEVERIFY:
			out += "CERTIFICATEVERIFY"

		case CHANGECIPHERSPEC:
			out += "CHANGECIPHERSPEC"

		case CLIENTHELLO:
			out += "CLIENTHELLO"

		case CLIENTKEYEXCHANGE:
			out += "CLIENTKEYEXCHANGE"

		case FINISHED:
			out += "FINISHED"

		case SERVERHELLO:
			out += "SERVERHELLO"

		case SERVERHELLODONE:
			out += "SERVERHELLODONE"

		case SERVERKEYEXCHANGE:
			out += "SERVERKEYEXCHANGE"

		default:
			out += "UNKNOWN"
		}

		if i < len(l)-1 {
			out += ", "
		}
	}

	return out + "]"
}
