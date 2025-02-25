package handshake

import (
	"fmt"

	evilmac "github.com/julinox/statemaquina"
)

const (
	CERTIFICATE        = 1 << 0
	CERTIFICATEREQUEST = 1 << 1
	CHANGECIPHERSPEC   = 1 << 2
	CLIENTHELLO        = 1 << 3
	CLIENTKEYEXCHANGE  = 1 << 4
	FINISHED           = 1 << 5
	SERVERHELLO        = 1 << 6
	SERVERHELLODONE    = 1 << 7
	SERVERKEYEXCHANGE  = 1 << 8
)

type Certificate interface {
	evilmac.State
	Handle([]byte) error
}

type CertificateRequest interface {
	evilmac.State
	Handle([]byte) error
}

type ChangeCipherSpec interface {
	evilmac.State
	Handle([]byte) error
}

type ClientHello interface {
	evilmac.State
	Handle([]byte) error
}

type ClientKeyExchange interface {
	evilmac.State
	Handle([]byte) error
}

type Finished interface {
	evilmac.State
	Handle([]byte) error
}

type ServerHello interface {
	evilmac.State
	Handle([]byte) error
}

type ServerHelloDone interface {
	evilmac.State
	Handle([]byte) error
}

type ServerKeyExchange interface {
	evilmac.State
	Handle([]byte) error
}

type Handshake struct {
	Cert           Certificate
	CertRequest    CertificateRequest
	ChgCph         ChangeCipherSpec
	ClientHelo     ClientHello
	ClientKeyExch  ClientKeyExchange
	Finish         Finished
	ServerHelo     ServerHello
	ServerHeloDone ServerHelloDone
	ServerKeyExch  ServerKeyExchange
	Contexto       HandShakeContext
	TLSHeader      Header
}

func NewHandshake(ctx HandShakeContext) (*Handshake, error) {

	var newHandshake Handshake

	if ctx == nil {
		return nil, fmt.Errorf("nil HandshakeContext object")
	}

	newHandshake.Contexto = ctx
	newHandshake.Cert = NewCertificate()
	newHandshake.CertRequest = NewCertificateRequest()
	newHandshake.ChgCph = NewChangeCipherSpec()
	newHandshake.ClientHelo = NewClientHello()
	newHandshake.ClientKeyExch = NewClientKeyExchange()
	newHandshake.Finish = NewFinished()
	newHandshake.ServerHelo = NewServerHello()
	newHandshake.ServerHeloDone = NewServerHelloDone()
	newHandshake.ServerKeyExch = NewServerKeyExchange()
	newHandshake.TLSHeader = NewHeader()
	if err := checkHandshakeInit(&newHandshake); err != nil {
		return nil, fmt.Errorf("handshake object creation: %v", err)
	}

	return &newHandshake, nil
}

func checkHandshakeInit(hsk *Handshake) error {

	if hsk == nil {
		return fmt.Errorf("nil Handshake object")
	}

	if hsk.Cert == nil {
		return fmt.Errorf("nil Certificate object")
	}

	if hsk.CertRequest == nil {
		return fmt.Errorf("nil CertificateRequest object")
	}

	if hsk.ChgCph == nil {
		return fmt.Errorf("nil ChangeCipherSpec object")
	}

	if hsk.ClientHelo == nil {
		return fmt.Errorf("nil ClientHello object")
	}

	if hsk.ClientKeyExch == nil {
		return fmt.Errorf("nil ClientKeyExchange object")
	}

	if hsk.Finish == nil {
		return fmt.Errorf("nil Finished object")
	}

	if hsk.ServerHelo == nil {
		return fmt.Errorf("nil ServerHello object")
	}

	if hsk.ServerHeloDone == nil {
		return fmt.Errorf("nil ServerHelloDone object")
	}

	if hsk.ServerKeyExch == nil {
		return fmt.Errorf("nil ServerKeyExchange object")
	}

	if hsk.Contexto == nil {
		return fmt.Errorf("nil HandShakeContext object")
	}

	if hsk.TLSHeader == nil {
		return fmt.Errorf("nil Header object")
	}

	return nil
}
