package handshake

import (
	"crypto/x509"
	"fmt"
	"net"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/cipherspec"

	"github.com/sirupsen/logrus"
)

const (
	CLIENTCERTIFICATE = 3
	SERVERCERTIFICATE = 7
	CLIENTRANDOM      = 31
	SERVERRANDOM      = 35
	PREMASTERSECRET   = 37
	MASTERSECRET      = 39
	CIPHERSPECCLIENT  = 41
	CIPHERSPECSERVER  = 43
	FINISHEDSERVER    = 47
)

type prfData struct {
	clientRandom    []byte
	serverRandom    []byte
	preMasterSecret []byte
	masterSecret    []byte
}

type xHandhsakeContextData struct {
	certificate        []byte
	certificateRequest []byte
	certificateVerify  []byte
	clientCertificate  []byte
	changeCipherSpec   []byte
	clientHello        []byte
	clientKeyExchange  []byte
	finished           []byte
	finishedServer     []byte
	serverHello        []byte
	serverHelloDone    []byte
	serverKeyExchange  []byte
	prf                prfData
	serverCert         *x509.Certificate
	msgHello           *MsgHello
	cipherSuite        uint16
	macMode            int
	transitionStage    int
	order              []int
	expected           int
	keys               *tlssl.SessionKeys
	specClient         cipherspec.CipherSpec
	specServer         cipherspec.CipherSpec
	completed          bool
	extensions         map[uint16]bool
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
	SetMacMode(int)
	GetMacMode() int
	SetKeys(*tlssl.SessionKeys)
	GetKeys() *tlssl.SessionKeys
	SetCipherSpec(int, cipherspec.CipherSpec)
	GetCipherSpec(int) cipherspec.CipherSpec
	SetTransitionStage(int)
	GetTransitionStage() int
	SetExtension(uint16)
	GetExtension(uint16) bool
	GetComms() net.Conn
	Order() []int
	AppendOrder(int) error
	PrintOrder() string
	Expected() int
	AppendExpected(int)
	UnAppendExpected(int)
	PrintExpected() string
	SendCtxBuff([]int) error
	Send([]byte) error
	IsCompleted() bool
	SetCompleted(bool)
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
	newContext.data.macMode = tlssl.MODE_MTE
	newContext.data.extensions = make(map[uint16]bool)
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
		x.data.certificateVerify = buff

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

	case FINISHEDSERVER:
		x.data.finishedServer = buff

	case SERVERHELLO:
		x.data.serverHello = buff

	case SERVERHELLODONE:
		x.data.serverHelloDone = buff

	case SERVERKEYEXCHANGE:
		x.data.serverKeyExchange = buff

	case CLIENTRANDOM:
		x.data.prf.clientRandom = buff

	case SERVERRANDOM:
		x.data.prf.serverRandom = buff

	case PREMASTERSECRET:
		x.data.prf.preMasterSecret = buff

	case MASTERSECRET:
		x.data.prf.masterSecret = buff
	}
}

func (x *xHandhsakeContext) GetBuffer(op int) []byte {

	switch op {
	case CERTIFICATE:
		return x.data.certificate

	case CERTIFICATEREQUEST:
		return x.data.certificateRequest

	case CERTIFICATEVERIFY:
		return x.data.certificateVerify

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

	case FINISHEDSERVER:
		return x.data.finishedServer

	case SERVERHELLO:
		return x.data.serverHello

	case SERVERHELLODONE:
		return x.data.serverHelloDone

	case SERVERKEYEXCHANGE:
		return x.data.serverKeyExchange

	case CLIENTRANDOM:
		return x.data.prf.clientRandom

	case SERVERRANDOM:
		return x.data.prf.serverRandom

	case PREMASTERSECRET:
		return x.data.prf.preMasterSecret

	case MASTERSECRET:
		return x.data.prf.masterSecret
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

func (x *xHandhsakeContext) SetMacMode(mode int) {
	x.data.macMode = mode
}

func (x *xHandhsakeContext) GetMacMode() int {
	return x.data.macMode
}

func (x *xHandhsakeContext) SetTransitionStage(stage int) {
	x.data.transitionStage = stage
}

func (x *xHandhsakeContext) SetKeys(keys *tlssl.SessionKeys) {
	x.data.keys = keys
}

func (x *xHandhsakeContext) GetKeys() *tlssl.SessionKeys {
	return x.data.keys
}

func (x *xHandhsakeContext) SetCipherSpec(who int, cs cipherspec.CipherSpec) {

	switch who {
	case CIPHERSPECCLIENT:
		x.data.specClient = cs
	case CIPHERSPECSERVER:
		x.data.specServer = cs
	}
}

func (x *xHandhsakeContext) GetCipherSpec(who int) cipherspec.CipherSpec {

	switch who {
	case CIPHERSPECCLIENT:
		return x.data.specClient
	case CIPHERSPECSERVER:
		return x.data.specServer
	}

	return nil
}

func (x *xHandhsakeContext) GetTransitionStage() int {
	return x.data.transitionStage
}

func (x *xHandhsakeContext) SetExtension(extID uint16) {

	if _, exists := x.data.extensions[extID]; !exists {
		x.data.extensions[extID] = true
	}
}

func (x *xHandhsakeContext) GetExtension(extID uint16) bool {

	if _, exists := x.data.extensions[extID]; exists {
		return true
	}

	return false
}

func (x *xHandhsakeContext) GetComms() net.Conn {
	return x.coms
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
	return HandshakeNameList(x.data.order)
}

// All posible handshake messages from client
// CERTIFICATE, CLIENTKEYEXCHANGE, CERTIFICATEVERIFY,
// CHANGECIPHERSPEC, FINISHED
func (x *xHandhsakeContext) Expected() int {
	return x.data.expected
}

func (x *xHandhsakeContext) AppendExpected(op int) {

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

func (x *xHandhsakeContext) UnAppendExpected(op int) {

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

	return HandshakeNameList(expected)
}

func (x *xHandhsakeContext) SendCtxBuff(ids []int) error {

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
			outBuff = append(outBuff, x.data.certificateVerify...)
			x.lg.Debug("Sending CERTIFICATEVERIFY")

		case CHANGECIPHERSPEC:
			outBuff = append(outBuff, x.data.changeCipherSpec...)
			x.lg.Debug("Sending CHANGECIPHERSPEC")

		case CLIENTHELLO:
			continue

		case CLIENTKEYEXCHANGE:
			outBuff = append(outBuff, x.data.clientKeyExchange...)
			x.lg.Debug("Sending CLIENTKEYEXCHANGE")

		case FINISHED:
			outBuff = append(outBuff, x.data.finished...)
			x.lg.Debug("Sending FINISHED")

		case FINISHEDSERVER:
			outBuff = append(outBuff, x.data.finishedServer...)
			x.lg.Debug("Sending FINISHEDSERVER")

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

func (x *xHandhsakeContext) Send(buffer []byte) error {

	if buffer == nil {
		return systema.ErrNilParams
	}

	return x.sendData(buffer)
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

func (x *xHandhsakeContext) IsCompleted() bool {
	return x.data.completed
}

func (x *xHandhsakeContext) SetCompleted(completed bool) {
	x.data.completed = completed
}
