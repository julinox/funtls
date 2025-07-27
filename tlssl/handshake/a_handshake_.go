package handshake

import (
	"fmt"

	"github.com/julinox/funtls/tlssl"

	evilmac "github.com/julinox/statemaquina"
)

const (
	COMPLETEHANDSHAKE  = 0
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
	Contexto        HandShakeContext
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

type AllContexts struct {
	Hctx HandShakeContext
	Tctx *tlssl.TLSContext
}

type stateBasicInfo struct {
	nextState int
	ctx       HandShakeContext
}

func HandshakeName(h int) string {

	switch h {
	case CERTIFICATE:
		return "CERTIFICATE"
	case CERTIFICATEREQUEST:
		return "CERTIFICATEREQUEST"
	case CERTIFICATEVERIFY:
		return "CERTIFICATEVERIFY"
	case CHANGECIPHERSPEC:
		return "CHANGECIPHERSPEC"
	case CLIENTHELLO:
		return "CLIENTHELLO"
	case CLIENTKEYEXCHANGE:
		return "CLIENTKEYEXCHANGE"
	case FINISHED:
		return "FINISHED"
	case SERVERHELLO:
		return "SERVERHELLO"
	case SERVERHELLODONE:
		return "SERVERHELLODONE"
	case SERVERKEYEXCHANGE:
		return "SERVERKEYEXCHANGE"
	}

	return "UNKNOWN"
}

func HandshakeNameList(l []int) string {

	out := "["

	for i, v := range l {
		out += HandshakeName(v)

		if i < len(l)-1 {
			out += ", "
		}
	}

	return out + "]"
}

func checkHandshakeInit(hsk *Handshake) error {

	if hsk == nil {
		return fmt.Errorf("nil Handshake object")
	}

	if hsk.Contexto == nil {
		return fmt.Errorf("nil HandShakeContext object")
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
