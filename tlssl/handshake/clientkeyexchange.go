package handshake

import (
	"fmt"
	"tlesio/tlssl"
)

type xClientKeyExchange struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewClientKeyExchange(actx *AllContexts) ClientKeyExchange {

	var newX xClientKeyExchange

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xClientKeyExchange) Name() string {
	return "_ClientKeyExchange_"
}

func (x *xClientKeyExchange) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xClientKeyExchange) Handle() error {

	if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATEVERIFY
	} else {
		x.nextState = CHANGECIPHERSPEC
	}

	fmt.Println("I AM: ", x.Name())
	return nil
}
