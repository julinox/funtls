package handshake

import (
	"fmt"

	"github.com/julinox/funtls/tlssl"
	ex "github.com/julinox/funtls/tlssl/extensions"
	ke "github.com/julinox/funtls/tlssl/keyexchange"
	"github.com/julinox/funtls/tlssl/names"
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

	var err error
	var keyEx ke.KeyExchange

	x.tCtx.Lg.Tracef("Running state: %v", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v", x.Name())
	dataSG := x.ctx.GetMsgHello().Extensions[ex.EXT_SUPPORTED_GROUPS]
	//dataSA := x.ctx.GetMsgHello().Extensions[ex.EXT_SIGNATURE_ALGORITHMS]

	cs := x.tCtx.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if cs == nil {
		return fmt.Errorf("cipher suite get err(%v)", x.Name())
	}
	switch cs.Info().KeyExchange {
	case names.KX_DHE:
		keyEx, err = ke.DHEphemeral(parseSG(dataSG))
	default:
		return fmt.Errorf("unknow server key exchange method")
	}

	if err != nil {
		return err
	}

	if keyEx == nil {
		return fmt.Errorf("nil key exchange interface")
	}

	keyEx.Params()
	if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATEREQUEST
	} else {
		x.nextState = SERVERHELLODONE
	}

	return nil
}

// Handle antes de la interface "KeyExchange"
/*
func (x *xServerKeyExchange) Handle() error {

	x.tCtx.Lg.Tracef("Running state: %v", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v", x.Name())
	dataSG := x.ctx.GetMsgHello().Extensions[ex.EXT_SUPPORTED_GROUPS]
	dataSA := x.ctx.GetMsgHello().Extensions[ex.EXT_SIGNATURE_ALGORITHMS]
	certPrivKey := x.tCtx.CertPKI.GetPrivateKey(x.ctx.GetCertFingerprint())
	if certPrivKey == nil {
		return fmt.Errorf("cert private key not found")
	}

	kxData := kx.KXData{
		CliRandom:  x.ctx.GetBuffer(CLIENTRANDOM),
		SrvRandom:  x.ctx.GetBuffer(SERVERRANDOM),
		SG:         parseSG(dataSG),
		SA:         parseSA(dataSA),
		PrivateKey: certPrivKey,
	}

	// ---------------------- Intercept ----------------------------
	kx.DHEphemeral(kxData.SG)
	// ---------------------- Intercept ----------------------------/

	cs := x.tCtx.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if cs == nil {
		return fmt.Errorf("ciphersuite not found")
	}

	kxParams, err := cs.ServerKX(&kxData)
	if err != nil {
		return err
	}

	if kxParams == nil {
		return fmt.Errorf("nil key exchange params")
	}

	hd := tlssl.TLSHeadsHandShakePacket(tlssl.HandshakeTypeServerKeyExchange,
		len(kxParams.Buffer))
	x.ctx.SetSkeParams(kxParams)
	x.ctx.SetBuffer(SERVERKEYEXCHANGE, append(hd, kxParams.Buffer...))
	x.ctx.AppendOrder(SERVERKEYEXCHANGE)
	if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATEREQUEST
	} else {
		x.nextState = SERVERHELLODONE
	}

	return nil
}
*/

func parseSG(data any) []uint16 {

	if data == nil {
		return []uint16{}
	}

	esg, ok := data.(*ex.ExtSupportedGroupsData)
	if !ok || esg.Len == 0 {
		return []uint16{}
	}

	return esg.Groups
}

func parseSA(data any) []uint16 {

	if data == nil {
		return []uint16{}
	}

	esa, ok := data.(*ex.ExtSignAlgoData)
	if !ok || esa.Len == 0 {
		return []uint16{}
	}

	return esa.Algos
}

func printSG(sg []uint16) {

	for _, g := range sg {
		fmt.Println(names.SupportedGroups[g])
	}
}

func printSA(sa []uint16) {

	for _, a := range sa {
		fmt.Println(names.SignHashAlgorithms[a])
	}
}
