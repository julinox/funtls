package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/suite"
)

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

	//var err error

	x.tCtx.Lg.Tracef("Running state: %v(CLIENT)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(CLIENT)", x.Name())

	// Get the handshake messages (in order) to hash them
	hskMsgs := x.handshakeMessagesOrder()
	if hskMsgs == nil {
		return fmt.Errorf("nil handshake messages buffer(%v)", x.Name())
	}

	// computed verify data
	calcVerify, err := x.calculateVD(hskMsgs, _VERIFY_DATA_LABEL_CLIENT)
	if err != nil {
		return err
	}

	// Get the verify data from the client
	cs := x.ctx.GetCipherScpec(CIPHERSPECCLIENT)
	if cs == nil {
		return fmt.Errorf("nil cipher spec client(%v)", x.Name())
	}

	// Get the "Finished" message
	finished := x.ctx.GetBuffer(FINISHED)
	tpt, err := cs.DecryptRecord(&tlssl.TLSCipherText{
		Header:   tlssl.TLSHead(finished[:tlssl.TLS_HEADER_SIZE]),
		Fragment: finished[tlssl.TLS_HEADER_SIZE:],
	})

	if err != nil {
		return err
	}

	content := tpt.Fragment
	if len(content) < tlssl.TLS_HANDSHAKE_SIZE+tlssl.VERIFYDATALEN {
		return fmt.Errorf("invalid Finished content-buffer len(%v)", x.Name())
	}

	x.tCtx.Lg.Tracef("Computed/Received verify data: %x / %x", calcVerify,
		content[tlssl.TLS_HANDSHAKE_SIZE:])
	verifyData := content[tlssl.TLS_HANDSHAKE_SIZE:]
	if !hmac.Equal(calcVerify, verifyData) {
		return fmt.Errorf("verify data mismatch(%v)", x.Name())
	}

	finishedMsg := append(tlssl.TLSHeadPacket(tpt.Header), content...)
	x.ctx.SetBuffer(FINISHED, finishedMsg)
	x.ctx.AppendOrder(FINISHED)
	x.nextState = TRANSITION
	return nil
}

// Data to send: Finished message(handshake header + verify data)
func (x *xFinished) finishedServer() error {

	var err error

	myself := systema.MyName()
	x.tCtx.Lg.Tracef("Running state: %v(SERVER)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(SERVER)", x.Name())
	/*cs := x.ctx.GetCipherScpec(CIPHERSPECSERVER)
	if cs == nil {
		return fmt.Errorf("GetCipherScpec(%v)", myself)
	}*/

	// -------------------------------------- CIPHERSPEC 2
	cs2 := x.ctx.GetCipherSpec2(CIPHERSPECSERVER)
	if cs2 == nil {
		return fmt.Errorf("GetCipherSpec2(%v)", myself)
	}
	// ---------------------------------------------------

	// Get the handshake messages (in order) to hash them
	hskMsgs := x.handshakeMessagesOrder()
	if hskMsgs == nil {
		return fmt.Errorf("handshakeMessagesOrder%v)", myself)
	}

	// computed verify data
	calcVerify, err := x.calculateVD(hskMsgs, _VERIFY_DATA_LABEL_SERVER)
	if err != nil {
		return fmt.Errorf("calculateVD(%v): %v", myself, err)
	}

	// Cipherspec1
	data1 := tlssl.TLSHeadHandShakePacket(&tlssl.TLSHeaderHandshake{
		HandshakeType: tlssl.HandshakeTypeFinished,
		Len:           0x0c,
	})

	x.tCtx.Lg.Debugf("Computed verify data(SERVER): %x", calcVerify)
	aux1 := append(data1, calcVerify...)

	// -------------------------------------- CIPHERSPEC 2
	packet, err0 := cs2.EncryptRec(tlssl.ContentTypeHandshake, aux1)
	if err0 != nil {
		x.tCtx.Lg.Errorf("EncryptRec(%v): %v", myself, err0)
		return fmt.Errorf("EncryptRec(%v): %v", myself, err0)
	}

	// ---------------------------------------------------

	/*tpt := &tlssl.TLSPlaintext{
		Header:   &tlssl.TLSHeader{ContentType: tlssl.ContentTypeHandshake},
		Fragment: append(data1, calcVerify...)}

	tct, err := cs.EncryptRecord(tpt)
	if err != nil {
		return fmt.Errorf("EncryptRecord(%v)", myself)
	}

	cipherType := x.ctx.GetCipherScpec(CIPHERSPECSERVER).CipherType()
	packet, err := tct.Packet(cipherType, true)
	if err != nil {
		return fmt.Errorf("TLSCipherText packet creation(%v)", myself)
	}*/

	//fmt.Printf("PACKETO: %x\n", packet)
	x.ctx.SetBuffer(FINISHEDSERVER, packet)
	//x.ctx.SetBuffer(FINISHEDSERVER, packet)
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
		case FINISHED:
			aux = x.ctx.GetBuffer(FINISHED)
		case SERVERHELLO:
			aux = x.ctx.GetBuffer(SERVERHELLO)
		case SERVERHELLODONE:
			aux = x.ctx.GetBuffer(SERVERHELLODONE)
		case SERVERKEYEXCHANGE:
			aux = x.ctx.GetBuffer(SERVERKEYEXCHANGE)
		default:
			continue
		}

		hashMe = append(hashMe, aux[tlssl.TLS_HEADER_SIZE:]...)
	}

	return hashMe
}

// Calculate the verify data.
// The label is "client finished" or "server finished"
// The verify data is the first 12 bytes of the PRF output
// Hash function is SHA256 (as defined in the RFC)
func (x *xFinished) calculateVD(hskMsgs []byte, label string) ([]byte, error) {

	var err error

	st := x.tCtx.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if st == nil {
		return nil, fmt.Errorf("error getting TLS Suite(%v)", x.Name())
	}

	keyMake, err := tlssl.NewKeymaker(suite.SHA256, 32)
	if err != nil {
		return nil, fmt.Errorf("error creating Keymaker(%v)", x.Name())
	}

	masterSecret := x.ctx.GetBuffer(MASTERSECRET)
	if len(masterSecret) <= 0 {
		return nil, fmt.Errorf("invalid master secret buffer(%v)", x.Name())
	}

	// Hash the handshake messages
	hasher := sha256.New()
	hasher.Write(hskMsgs)
	expectedVerify := keyMake.PRF(masterSecret, label, hasher.Sum(nil))
	if len(expectedVerify) <= tlssl.VERIFYDATALEN {
		return nil, fmt.Errorf("expected verify data calc(%v)", x.Name())
	}

	return expectedVerify[:tlssl.VERIFYDATALEN], nil
}
