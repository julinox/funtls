package handshake

import (
	"fmt"
	"tlesio/tlssl"
	"tlesio/tlssl/suite"
)

const _VERIFY_DATA_SZ = 12
const _VERIFY_DATA_LABEL_CLIENT = "client finished"
const _VERIFY_DATA_LABEL_SERVER = "server finished"

type xFinished struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewFinished(actx *AllContexts) Finished {

	var newX xFinished

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
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

	var err error

	x.tCtx.Lg.Tracef("Running state: %v(CLIENT)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(CLIENT)", x.Name())

	// Get the handshake messages (in order) to hash them
	hskMsgs := x.handshakeMessagesOrder()
	if hskMsgs == nil {
		return fmt.Errorf("nil handshake messages buffer(%v)", x.Name())
	}

	// computed verify data
	calcVerify, err := x.expectedVD(hskMsgs, _VERIFY_DATA_LABEL_CLIENT)
	if err != nil {
		return err
	}

	// Get the verify data from the client
	cs := x.ctx.GetCipherScpec(CIPHERSPECCLIENT)
	if cs == nil {
		return fmt.Errorf("nil cipher spec client(%v)", x.Name())
	}

	tct, err := cs.Decode(x.ctx.GetBuffer(FINISHED))
	if err != nil {
		return err
	}

	content := cs.Content(tct)
	if content == nil {
		return fmt.Errorf("nil content buffer(%v)", x.Name())
	}

	fmt.Printf("CONTENIDO: %x\n", content)
	x.tCtx.Lg.Tracef("Expected verify data: %x", calcVerify)
	x.nextState = TRANSITION
	return nil
}

func (x *xFinished) finishedServer() error {

	x.tCtx.Lg.Tracef("Running state: %v(SERVER)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(SERVER)", x.Name())
	x.nextState = TRANSITION
	return nil
}

// Get the handshake messages in order (TLS Header is not included)
func (x *xFinished) handshakeMessagesOrder() []byte {

	var hashMe []byte

	for _, m := range x.ctx.Order() {
		var aux []byte

		switch m {
		case CERTIFICATE:
			aux = x.ctx.GetBuffer(CERTIFICATE)
		case CERTIFICATEREQUEST:
			aux = x.ctx.GetBuffer(CERTIFICATEREQUEST)
		case CERTIFICATEVERIFY:
			aux = x.ctx.GetBuffer(CERTIFICATEVERIFY)
		case CLIENTHELLO:
			aux = x.ctx.GetBuffer(CLIENTHELLO)
		case CLIENTCERTIFICATE:
			aux = x.ctx.GetBuffer(CLIENTCERTIFICATE)
		case CLIENTKEYEXCHANGE:
			aux = x.ctx.GetBuffer(CLIENTKEYEXCHANGE)
		case SERVERHELLO:
			aux = x.ctx.GetBuffer(SERVERHELLO)
		case SERVERHELLODONE:
			aux = x.ctx.GetBuffer(SERVERHELLODONE)
		case SERVERKEYEXCHANGE:
			aux = x.ctx.GetBuffer(SERVERKEYEXCHANGE)
		}

		hashMe = append(hashMe, aux[tlssl.TLS_HEADER_SIZE:]...)
	}

	return hashMe
}

func (x *xFinished) expectedVD(hskMsgs []byte, label string) ([]byte, error) {

	var err error

	st := x.tCtx.Modz.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if st == nil {
		return nil, fmt.Errorf("error getting TLS Suite(%v)", x.Name())
	}

	keyMake, err := tlssl.NewKeymaker(suite.SHA256, 32)
	if err != nil {
		return nil, fmt.Errorf("error creating Keymaker(%v)", x.Name())
	}

	// Get the master secret
	masterSecret := x.ctx.GetBuffer(MASTERSECRET)
	if len(masterSecret) <= 0 {
		return nil, fmt.Errorf("invalid master secret buffer(%v)", x.Name())
	}

	hash, err := st.HashMe(hskMsgs)
	if err != nil {
		return nil, err
	}

	// Get the PRF
	expectedVerify := keyMake.PRF(masterSecret, label, hash)
	if len(expectedVerify) <= _VERIFY_DATA_SZ {
		return nil, fmt.Errorf("expected verify data calc(%v)", x.Name())
	}

	return expectedVerify[:_VERIFY_DATA_SZ], nil
}
