package handshake

import (
	"fmt"

	evilmac "github.com/julinox/statemaquina"
	"github.com/sirupsen/logrus"
)

const (
	CERTIFICATE        = 1 << 0
	CERTIFICATEREQUEST = 1 << 1
	CERTIFICATEVERIFY  = 1 << 2
	CHANGECIPHERSPEC   = 1 << 3
	CLIENTHELLO        = 1 << 4
	CLIENTKEYEXCHANGE  = 1 << 5
	FINISHED           = 1 << 6
	SERVERHELLO        = 1 << 7
	SERVERHELLODONE    = 1 << 8
	SERVERKEYEXCHANGE  = 1 << 9
	TRANSITION         = 1 << 10
)

type Certificate interface {
	evilmac.State
	Handle() error
}

type CertificateRequest interface {
	evilmac.State
	Handle() error
}

type CertificateVerify interface {
	evilmac.State
	Handle() error
}

type ChangeCipherSpec interface {
	evilmac.State
	Handle() error
}

type ClientHello interface {
	evilmac.State
	Handle() error
}

type ClientKeyExchange interface {
	evilmac.State
	Handle() error
}

type Finished interface {
	evilmac.State
	Handle() error
}

type ServerHello interface {
	evilmac.State
	Handle() error
}

type ServerHelloDone interface {
	evilmac.State
	Handle() error
}

type ServerKeyExchange interface {
	evilmac.State
	Handle() error
}

type Transition interface {
	evilmac.State
	Handle() error
}

type Handshake struct {
	Contexto  HandShakeContext
	TLSHeader Header

	// Handshake states
	Cert            Certificate
	CertificateReq  CertificateRequest
	CertificateVerf CertificateVerify
	ChgCph          ChangeCipherSpec
	ClientHelo      ClientHello
	ClientKeyExch   ClientKeyExchange
	Finish          Finished
	ServerHelo      ServerHello
	ServerHeloDone  ServerHelloDone
	ServerKeyExch   ServerKeyExchange
	Transit         Transition
}

type stateBasicInfo struct {
	nextState int
	//nextError error
	ctx HandShakeContext
}

func NewHandshake(lg *logrus.Logger, ctx HandShakeContext) (*Handshake, error) {

	var newHandshake Handshake

	if ctx == nil {
		return nil, fmt.Errorf("nil HandshakeContext object")
	}

	newHandshake.Contexto = ctx
	newHandshake.TLSHeader = NewHeader()
	newHandshake.Cert = NewCertificate(ctx)
	newHandshake.CertificateReq = NewCertificateRequest(ctx)
	newHandshake.CertificateVerf = NewCertificateVerify(ctx)
	newHandshake.ChgCph = NewChangeCipherSpec(ctx)
	newHandshake.ClientHelo = NewClientHello(ctx)
	newHandshake.ClientKeyExch = NewClientKeyExchange(ctx)
	newHandshake.Finish = NewFinished(ctx)
	newHandshake.ServerHelo = NewServerHello(ctx)
	newHandshake.ServerHeloDone = NewServerHelloDone(ctx)
	newHandshake.ServerKeyExch = NewServerKeyExchange(ctx)
	newHandshake.Transit = NewTransition(lg, ctx)
	if err := checkHandshakeInit(&newHandshake); err != nil {
		return nil, fmt.Errorf("handshake object creation: %v", err)
	}

	return &newHandshake, nil
}

func checkHandshakeInit(hsk *Handshake) error {

	if hsk == nil {
		return fmt.Errorf("nil Handshake object")
	}

	if hsk.Contexto == nil {
		return fmt.Errorf("nil HandShakeContext object")
	}

	if hsk.TLSHeader == nil {
		return fmt.Errorf("nil Header object")
	}

	if hsk.Cert == nil {
		return fmt.Errorf("nil Certificate object")
	}

	if hsk.CertificateReq == nil {
		return fmt.Errorf("nil CertificateRequest object")
	}

	if hsk.CertificateVerf == nil {
		return fmt.Errorf("nil CertificateVerify object")
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

	if hsk.Transit == nil {
		return fmt.Errorf("nil Transition object")
	}

	return nil
}
