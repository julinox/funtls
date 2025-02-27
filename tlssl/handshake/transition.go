package handshake

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

const (
	STAGE_SERVERHELLODONE = iota + 1
	STAGE_FINISHED_CLIENT
	STAGE_FINISHED_SERVER
)

type xTransition struct {
	stateBasicInfo
	lg *logrus.Logger
}

func NewTransition(lg *logrus.Logger, ctx HandShakeContext) Transition {

	var newX xTransition

	if lg == nil || ctx == nil {
		return nil
	}

	newX.lg = lg
	newX.ctx = ctx
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
		x.lg.Info("Complete Handshake")
		return nil

	default:
		return fmt.Errorf("Invalid transition stage")
	}
}

func (x *xTransition) transitServerHelloDone() error {

	x.lg.Info("Transitioning from SERVERHELLODONE")
	if x.ctx.GetOptClientAuth() {
		x.nextState = CERTIFICATE
	} else {
		x.nextState = CLIENTKEYEXCHANGE
	}

	x.ctx.SetTransitionStage(STAGE_FINISHED_CLIENT)
	return nil
}

func (x *xTransition) transitFinishedClient() error {

	x.lg.Info("Transitioning from FINISHED_CLIENT")
	x.nextState = CHANGECIPHERSPEC
	x.ctx.SetTransitionStage(STAGE_FINISHED_SERVER)
	return nil
}
