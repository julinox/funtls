package handshake

import (
	"fmt"
	"tlesio/tlssl"
	"tlesio/tlssl/suites"
)

type xCertificate struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewCertificate(actx *AllContexts) Certificate {

	var newX xCertificate

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xCertificate) Name() string {
	return "_Certificate_"
}

func (x *xCertificate) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xCertificate) Handle() error {

	switch x.ctx.GetTransitionStage() {
	case STAGE_SERVERHELLODONE:
		return x.certificateServer()

	case STAGE_FINISHED_CLIENT:
		return x.certificateClient()

	default:
		return fmt.Errorf("%v: invalid transition stage", x.Name())
	}
}

func (x *xCertificate) certificateServer() error {

	cs := x.tCtx.Modz.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if cs == nil {
		return fmt.Errorf("%v: invalid cipher suite", x.Name())
	}

	if cs.Info().KeyExchange == suites.DHE {
		x.nextState = SERVERKEYEXCHANGE

	} else if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATEREQUEST

	} else {
		x.nextState = SERVERHELLODONE
	}

	fmt.Printf("I AM: %v(SERVER)\n", x.Name())
	return nil
}

func (x *xCertificate) certificateClient() error {

	fmt.Printf("I AM: %v(CLIENT)\n", x.Name())
	x.nextState = CLIENTKEYEXCHANGE
	return nil
}
