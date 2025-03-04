package handshake

import "tlesio/tlssl"

type xServerHelloDone struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewServerHelloDone(actx *AllContexts) ServerHelloDone {

	var newX xServerHelloDone

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xServerHelloDone) Name() string {
	return "_ServerHelloDone_"
}

func (x *xServerHelloDone) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xServerHelloDone) Handle() error {

	x.tCtx.Lg.Tracef("Running state: %v", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v", x.Name())

	// Header
	buff := tlssl.TLSHeadsHandShakePacket(tlssl.HandshakeTypeServerHeloDone, 0)
	x.ctx.SetBuffer(SERVERHELLODONE, buff)
	x.ctx.AppendOrder(SERVERHELLODONE)
	x.nextState = TRANSITION
	return nil
}
