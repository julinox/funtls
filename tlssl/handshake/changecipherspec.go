package handshake

import (
	"fmt"
	"tlesio/tlssl"
)

const _MASTER_SECRET_SIZE_ = 48
const _MASTER_SECRET_LABEL_ = "master secret"

type xChangeCipherSpec struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewChangeCipherSpec(actx *AllContexts) ChangeCipherSpec {

	var newX xChangeCipherSpec

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xChangeCipherSpec) Name() string {
	return "_ChangeCipherSpec_"
}

func (x *xChangeCipherSpec) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xChangeCipherSpec) Handle() error {

	x.nextState = FINISHED
	switch x.ctx.GetTransitionStage() {
	case STAGE_FINISHED_CLIENT:
		return x.ccsClient()

	case STAGE_FINISHED_SERVER:
		return x.ccsServer()

	default:
		return fmt.Errorf("%v: invalid transition stage", x.Name())
	}
}

func (x *xChangeCipherSpec) ccsClient() error {

	x.tCtx.Lg.Tracef("Running state: %v(CLIENT)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(CLIENT)", x.Name())
	if err := x.masterSecreto(); err != nil {
		return err
	}

	return nil
}

func (x *xChangeCipherSpec) ccsServer() error {

	x.tCtx.Lg.Tracef("Running state: %v(SERVER)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(SERVER)", x.Name())
	return nil
}

// Hear it hear it! The dreaded master secret is here!
func (x *xChangeCipherSpec) masterSecreto() error {

	var seed []byte

	stt := x.tCtx.Modz.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if stt == nil {
		return fmt.Errorf("nil TLSSuite object(%v)", x.Name())
	}

	stInfo := stt.Info()
	if stInfo == nil {
		return fmt.Errorf("nil SuiteInfo object(%v)", x.Name())
	}

	keyMaker, err := NewKeymaker(stInfo.Hash, _MASTER_SECRET_SIZE_)
	if err != nil {
		return fmt.Errorf("NewKeymaker error(%v): %v", x.Name(), err)
	}

	preMasterSecret := x.ctx.GetBuffer(PREMASTERSECRET)
	if preMasterSecret == nil {
		return fmt.Errorf("nil PreMasterSecret buffer(%v)", x.Name())
	}

	seed = append(seed, x.ctx.GetBuffer(CLIENTRANDOM)...)
	seed = append(seed, x.ctx.GetBuffer(SERVERRANDOM)...)
	masterSecret := keyMaker.PRF(preMasterSecret, _MASTER_SECRET_LABEL_, seed)
	if masterSecret == nil {
		return fmt.Errorf("nil MasterSecret(%v)", x.Name())
	}

	if len(masterSecret) != _MASTER_SECRET_SIZE_ {
		return fmt.Errorf("invalid MasterSecret size(%v)", x.Name())
	}

	fmt.Println("------------------------ MASTER SECRET ------------------------")
	fmt.Printf("%x\n", masterSecret)
	fmt.Println("------------------------ MASTER SECRET ------------------------")
	return nil
}

// blockLen := 2 * (stInfo.KeySize + stInfo.IVSize + stInfo.KeySizeHMAC)
