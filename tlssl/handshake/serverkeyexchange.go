package handshake

import (
	"fmt"

	"github.com/julinox/funtls/tlssl"
	ex "github.com/julinox/funtls/tlssl/extensions"
	"github.com/julinox/funtls/tlssl/suite/dhe"
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

	// Extension 0x000A = supported_groups
	data := x.ctx.GetMsgHello().Extensions[0x000A]
	if data == nil {
		return fmt.Errorf("%v: no ServerKeyExchange data found", x.Name())
	}

	rd, ok := data.(*ex.ExtSupportedGroupsData)
	if !ok {
		return fmt.Errorf("%v: invalid ServerKeyExchange data type", x.Name())
	}

	pp, err := dhe.NewDHEPms(rd.Groups)
	if err != nil {
		return fmt.Errorf("NewDHEPms (%v): %v", x.Name(), err)
	}

	x.tCtx.Lg.Infof("EL Grupo: %v", pp.GroupName)
	//return fmt.Errorf("ServerKeyExchange not implemented yet")
	if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATEREQUEST
	} else {
		x.nextState = SERVERHELLODONE
	}

	return nil
}
