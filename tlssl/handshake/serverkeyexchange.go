package handshake

import (
	"fmt"

	"github.com/julinox/funtls/tlssl"
)

type xServerKeyExchange struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewServerKeyExchange(actx *AllContexts) ServerKeyExchange {

	var newX xServerKeyExchange

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xServerKeyExchange) Name() string {
	return "_ServerKeyExchange_"
}

func (x *xServerKeyExchange) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xServerKeyExchange) Handle() error {

	if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATEREQUEST
	} else {
		x.nextState = SERVERHELLODONE
	}

	fmt.Println("I AM: ", x.Name())
	return nil
}
