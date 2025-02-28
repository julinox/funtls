package handshake

import "fmt"

type xFinished struct {
	stateBasicInfo
}

func NewFinished(ctx HandShakeContext) Finished {

	var newX xFinished

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xFinished) Name() string {
	return "_Finished_"
}

func (x *xFinished) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xFinished) Handle() error {

	switch x.ctx.GetTransitionStage() {
	case STAGE_FINISHED_CLIENT:
		return x.finishedClient()

	case STAGE_FINISHED_SERVER:
		return x.finishedServer()

	default:
		return fmt.Errorf("%v: invalid transition stage", x.Name())
	}
}

func (x *xFinished) finishedClient() error {

	x.nextState = TRANSITION
	fmt.Printf("I AM: %v(CLIENT)\n", x.Name())
	return nil
}

func (x *xFinished) finishedServer() error {

	x.nextState = TRANSITION
	fmt.Printf("I AM: %v(SERVER)\n", x.Name())
	return nil
}
