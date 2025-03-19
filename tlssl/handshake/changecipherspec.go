package handshake

import (
	"fmt"
	"tlesio/tlssl"
	"tlesio/tlssl/suite"
)

const _MASTER_SECRET_SIZE_ = 48
const _MASTER_SECRET_LABEL_ = "master secret"
const _KEY_EXPANSION_LABEL_ = "key expansion"

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
		return x.cipeherSpecClient()

	case STAGE_FINISHED_SERVER:
		return x.cipeherSpecServer()

	default:
		return fmt.Errorf("%v: invalid transition stage", x.Name())
	}
}

func (x *xChangeCipherSpec) cipeherSpecClient() error {

	x.tCtx.Lg.Tracef("Running state: %v(CLIENT)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(CLIENT)", x.Name())
	if err := x.masterSecreto(); err != nil {
		return err
	}

	if err := x.sessionKeys(); err != nil {
		return err
	}

	// create a new cipher spec
	st := x.tCtx.Modz.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if st == nil {
		return fmt.Errorf("nil TLSSuite object(%v)", x.Name())
	}

	clientKeys := x.ctx.GetKeys().ClientKeys
	newSpec := tlssl.NewTLSCipherSpec(st, &clientKeys, x.ctx.GetMacMode())
	if newSpec == nil {
		return fmt.Errorf("nil TLSCipherSpec object create(%v)", x.Name())
	}

	x.ctx.SetCipherScpec(CIPHERSPECCLIENT, newSpec)
	x.tCtx.Lg.Debug("Client CipherSpec created")
	return nil
}

func (x *xChangeCipherSpec) cipeherSpecServer() error {

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

	keyMaker, err := tlssl.NewKeymaker(stInfo.Hash, _MASTER_SECRET_SIZE_)
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

	x.ctx.SetBuffer(MASTERSECRET, masterSecret)
	x.tCtx.Lg.Info("MasterSecret generated")
	return nil
}

// Calculate session keys
func (x *xChangeCipherSpec) sessionKeys() error {

	var seed []byte
	var seshKeys tlssl.SessionKeys

	st := x.tCtx.Modz.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if st == nil {
		return fmt.Errorf("nil TLSSuite object(%v)", x.Name())
	}

	stInfo := st.Info()
	if stInfo == nil {
		return fmt.Errorf("nil SuiteInfo object(%v)", x.Name())
	}

	blockLen := 2 * (stInfo.KeySizeHMAC + stInfo.KeySize + stInfo.IVSize)
	kMake, err := tlssl.NewKeymaker(suite.SHA256, blockLen)
	if err != nil {
		return fmt.Errorf("nil Keymaker object(%v)", x.Name())
	}

	masterSecret := x.ctx.GetBuffer(MASTERSECRET)
	if masterSecret == nil {
		return fmt.Errorf("nil MasterSecret buffer(%v)", x.Name())
	}

	seed = append(seed, x.ctx.GetBuffer(SERVERRANDOM)...)
	seed = append(seed, x.ctx.GetBuffer(CLIENTRANDOM)...)
	keys := kMake.PRF(masterSecret, _KEY_EXPANSION_LABEL_, seed)
	if keys == nil {
		return fmt.Errorf("nil SessionKeys generation(%v)", x.Name())
	}

	if len(keys) != blockLen {
		return fmt.Errorf("invalid SessionKeys size(%v)", x.Name())
	}

	off := 0 // Offset (Called 'off' for space reasons)
	// MAC Client/Server
	seshKeys.ClientKeys.MAC = keys[0:stInfo.KeySizeHMAC]
	seshKeys.ServerKeys.MAC = keys[stInfo.KeySizeHMAC : 2*stInfo.KeySizeHMAC]
	off += 2 * stInfo.KeySizeHMAC

	// Key Client/Server
	seshKeys.ClientKeys.Key = keys[off : off+stInfo.KeySize]
	seshKeys.ServerKeys.Key = keys[off+stInfo.KeySize : off+2*stInfo.KeySize]
	off += 2 * stInfo.KeySize

	// IV Client/Server
	seshKeys.ClientKeys.IV = keys[off : off+stInfo.IVSize]
	seshKeys.ServerKeys.IV = keys[off+stInfo.IVSize : off+2*stInfo.IVSize]
	if err := checkKeys(&seshKeys, stInfo, x.Name()); err != nil {
		return err
	}

	x.ctx.SetKeys(&seshKeys)
	x.tCtx.Lg.Info("SessionKeys generated")
	return nil
}

func checkKeys(keys *tlssl.SessionKeys, info *suite.SuiteInfo, tag string) error {

	if keys == nil {
		return fmt.Errorf("nil SessionKeys object(%v)", tag)
	}

	if len(keys.ClientKeys.MAC) != info.KeySizeHMAC ||
		len(keys.ServerKeys.MAC) != info.KeySizeHMAC {
		return fmt.Errorf("invalid _Keys.MAC size(%v)", tag)
	}

	if len(keys.ClientKeys.Key) != info.KeySize ||
		len(keys.ServerKeys.Key) != info.KeySize {
		return fmt.Errorf("invalid _Keys.Key size(%v)", tag)
	}

	if len(keys.ClientKeys.IV) != info.IVSize ||
		len(keys.ServerKeys.IV) != info.IVSize {
		return fmt.Errorf("invalid _Keys.IV size(%v)", tag)
	}

	return nil
}
