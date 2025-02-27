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
		x.transitServerHelloDone()

	default:
		fmt.Println("????")
	}

	return nil
}

func (x *xTransition) transitServerHelloDone() {

	x.lg.Info("Transitioning to SERVERHELLODONE")
	if x.ctx.GetOptClientAuth() {
		x.nextState = CERTIFICATE
	} else {
		x.nextState = CLIENTKEYEXCHANGE
	}

	x.ctx.SetTransitionStage(STAGE_FINISHED_CLIENT)
}
