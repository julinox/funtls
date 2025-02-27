package handshake

import "fmt"

type xCertificate struct {
	stateBasicInfo
}

func NewCertificate(ctx HandShakeContext) Certificate {

	var newX xCertificate

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
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
		return fmt.Errorf("%v invalid transition stage", x.Name())
	}
}

func (x *xCertificate) certificateServer() error {

	dh := true
	if dh {
		x.nextState = SERVERKEYEXCHANGE

	} else if x.ctx.GetOptClientAuth() {
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
