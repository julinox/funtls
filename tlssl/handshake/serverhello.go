package handshake

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/julinox/funtls/tlssl"
	ex "github.com/julinox/funtls/tlssl/extensions"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

type xServerHello struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewServerHello(actx *AllContexts) ServerHello {

	var newX xServerHello

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xServerHello) Name() string {
	return "_ServerHello_"
}

func (x *xServerHello) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xServerHello) Handle() error {

	var serverHelloBuf []byte

	x.tCtx.Lg.Tracef("Running state: %v", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v", x.Name())
	msgHello := x.ctx.GetMsgHello()
	if msgHello == nil {
		return fmt.Errorf("nil MsgHello object")
	}

	serverHelloBuf = make([]byte, 0)
	// Version
	serverHelloBuf = append(serverHelloBuf, x.setVersion()...)

	// Random
	random, err := x.random()
	if err != nil {
		return fmt.Errorf("error generating server random: %v", err)
	}

	serverHelloBuf = append(serverHelloBuf, random[:]...)
	x.tCtx.Lg.Tracef("Field[Random(server)]: %x", random)

	// Session ID. No session resumption
	serverHelloBuf = append(serverHelloBuf, 0x00)

	// Cipher Suite
	err = x.chooseCSAndCert(msgHello)
	if err != nil {
		return err
	}

	cs := x.ctx.GetCipherSuite()
	serverHelloBuf = append(serverHelloBuf, byte(cs>>8), byte(cs))
	// "Compression methods"
	serverHelloBuf = append(serverHelloBuf, 0x00)
	// Extensions
	serverHelloBuf = append(serverHelloBuf, x.extensions(msgHello)...)
	// Headers
	header := tlssl.TLSHeadsHandShakePacket(tlssl.HandshakeTypeServerHello,
		len(serverHelloBuf))
	// Set server hello buffer and client and server random (which are
	// needed for the session keys generation)
	x.ctx.SetBuffer(SERVERHELLO, append(header, serverHelloBuf...))
	x.ctx.SetBuffer(SERVERRANDOM, random)
	x.ctx.AppendOrder(SERVERHELLO)

	// Encrypt-then-MAC extension
	// Set ETM mode always when the client supports it
	if x.ctx.GetExtension(0x0016) {
		x.ctx.SetMacMode(tlssl.MODE_ETM)
		x.tCtx.Lg.Info("Encrypt-then-MAC extension enabled")
	}

	x.nextState = CERTIFICATE
	return nil
}

func (x *xServerHello) setVersion() []byte {

	// Force TLS 1.2
	return []byte{0x03, 0x03}
}

func (x *xServerHello) random() ([]byte, error) {

	newBuff := make([]byte, 32)
	_, err := rand.Read(newBuff)
	if err != nil {
		return nil, err
	}

	return newBuff, nil
}

// Its important to know that the choosing of the cipher suite is tighly
// coupled with the choosing of the certificate.
//
// Rules/Anotations for choosing certificate (regarding a CS):
// * If KX with ECDH then SG list is required, and cert's curve must match
// one from the list. Note that when signing is required (ServerKeyExchange)
// and the CS requires an EC signing algorithm then the same curve choosed
// for KX must appears among the list of SignatureAlgorithms
//
// * For classic Diffie-Hellman no SG list is required (since it has fallback)
//
// * The cert must be signed by one of the algorithms within the SA list
// but its not a requierement to be same choosed for KX
//
// A certificate by itself does not define whether the Key Exchange (KX)
// uses static (EC)DH or ephemeral (EC)DHE. That is defined by the CS.
// In static (EC)DH, the same long-term private key is reused in every KX.
// This implies:
//   - The server must already possess the long-term (EC)DH private key
//   - Since the private key is already know then ServerKeyExchange step
//     is not needed (on the contrary ephimeral requires SKE)
//   - The certificate public key must correspond to that static private key
//   - The cert need 'KeyUsage keyAgreement0 for static (EC)DH (like RSA)
//
// In (EC)DHE, the server generates a fresh ephemeral key per handshake,
// and the certificate is only used to sign the ServerKeyExchange parameters.
// KeyAgreement is not required; DigitalSignature is enough.
func (x *xServerHello) chooseCSAndCert(cliMsg *MsgHello) error {

	sg := getSupportedGroups(cliMsg)
	sa := getSignatureAlgorithms(cliMsg)
	sni := getServerNameIndication(cliMsg)
	for _, cs := range cliMsg.CipherSuites {
		if !x.tCtx.TLSSuite.IsSupported(cs) {
			continue
		}

		st := x.tCtx.TLSSuite.GetSuite(cs)
		if st == nil {
			continue
		}

		fp := st.CertMe(&suite.CertMatch{
			SG:  sg,
			SA:  sa,
			SNI: sni,
		})

		if len(fp) > 0 {
			fmt.Println("Bingo")
			return fmt.Errorf("Encontramos el Certo pero forzamos el error")
		}
	}

	return fmt.Errorf("No ciphersuites match for the given clientHello")
}

func (x *xServerHello) extensions(cliMsg *MsgHello) []byte {

	var extsBuffer []byte

	extsBuffer = make([]byte, 2)
	for extID, extData := range cliMsg.Extensions {
		ext := x.tCtx.Exts.Get(extID)
		// Renegiation info skip
		if ext.ID() == 0xFF01 {
			continue
		}

		// This should never happen
		if ext == nil || extData == nil {
			x.tCtx.Lg.Warnf("nil (or missing data) for Extension: %v",
				ex.ExtensionName[extID])
			continue
		}

		auxBuffer, err := ext.PacketServerHelo(extData)
		if err != nil {
			x.tCtx.Lg.Errorf("Packet Extension(%v) : %v",
				ex.ExtensionName[extID], err)
			continue
		}

		if len(auxBuffer) == 0 {
			continue
		}

		extsBuffer = append(extsBuffer, auxBuffer...)
		x.ctx.SetExtension(ext.ID())
	}

	// Force renegotiation info
	rInfoBuff, err := x.tCtx.Exts.Get(0xFF01).PacketServerHelo(nil)
	if err != nil {
		x.tCtx.Lg.Errorf("Force Renegiation Info: %v", err)
	}

	extsBuffer = append(extsBuffer, rInfoBuff...)
	binary.BigEndian.PutUint16(extsBuffer, uint16(len(extsBuffer)-2))
	return extsBuffer
}

func getSupportedGroups(cliMsg *MsgHello) []uint16 {

	if cliMsg == nil {
		return []uint16{}
	}

	sgAux := cliMsg.Extensions[ex.EXT_SUPPORTED_GROUPS]
	if sgAux == nil {
		return []uint16{}
	}

	sgData, ok := sgAux.(*ex.ExtSupportedGroupsData)
	if !ok {
		return []uint16{}
	}

	return sgData.Groups
}

func getSignatureAlgorithms(cliMsg *MsgHello) []uint16 {

	fmt.Println("-------------------------DEBUG getsignaturealgorithms")
	return []uint16{
		names.RSA_PKCS1_SHA256,
		names.ECDSA_SECP384R1_SHA384,
		names.ECDSA_SECP256R1_SHA256,
	}
	fmt.Println("-------------------------DEBUG getsignaturealgorithms")
	if cliMsg == nil {
		return []uint16{}
	}

	saAux := cliMsg.Extensions[ex.EXT_SIGNATURE_ALGORITHMS]
	if saAux == nil {
		return []uint16{}
	}

	saData, ok := saAux.(*ex.ExtSignAlgoData)
	if !ok {
		return []uint16{}
	}

	return saData.Algos
}

func getServerNameIndication(cliMsg *MsgHello) []string {

	names := []string{}
	if cliMsg == nil {
		return names
	}

	sniAux := cliMsg.Extensions[ex.EXT_SERVER_NAME]
	if sniAux == nil {
		return names
	}

	sniData, ok := sniAux.(*ex.ExtSNIData)
	if !ok {
		return names
	}

	for _, name := range sniData.Names {
		names = append(names, name.Name)
	}
	return names
}
