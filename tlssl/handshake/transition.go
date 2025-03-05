package handshake

import (
	"fmt"
	"tlesio/tlssl"
)

const _BUFFER_SIZE_ = 2048
const _READ_TIMEOUT_ = 2
const (
	STAGE_SERVERHELLODONE = iota + 1
	STAGE_FINISHED_CLIENT
	STAGE_FINISHED_SERVER
)

type xTransition struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewTransition(actx *AllContexts) Transition {

	var newX xTransition

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xTransition) Name() string {
	return "_Transition_"
}

func (x *xTransition) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xTransition) Handle() error {

	switch x.ctx.GetTransitionStage() {
	case STAGE_SERVERHELLODONE:
		return x.transitServerHelloDone()

	case STAGE_FINISHED_CLIENT:
		return x.transitFinishedClient()

	case STAGE_FINISHED_SERVER:
		x.nextState = COMPLETEHANDSHAKE
		x.tCtx.Lg.Info("Complete Handshake")
		return nil

	default:
		return fmt.Errorf("%v: invalid transition stage", x.Name())
	}
}

func (x *xTransition) transitFinishedClient() error {

	x.tCtx.Lg.Debug("Transitioning from FINISHED_CLIENT")
	x.nextState = CHANGECIPHERSPEC
	x.ctx.SetTransitionStage(STAGE_FINISHED_SERVER)
	return nil
}
