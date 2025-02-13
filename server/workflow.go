package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"tlesio/systema"
	ifs "tlesio/tlssl/interfaces"
	cbf "tlesio/tlssl/interfaces/cryptobuff"
)

type wkf struct {
	ssl        *zzl
	cryptoBuff cbf.CryptoBuff
	conn       net.Conn
	buffer     []byte // Original buffer including TLS header
}

// Handle Handshake Request
func TLSMe(ssl *zzl, buff []byte, conn net.Conn) *wkf {

	var newWF wkf

	if ssl == nil || buff == nil || conn == nil {
		return nil
	}

	if len(buff) <= 45 {
		ssl.lg.Error("buffer is too small for a client hello")
		return nil
	}

	newWF.ssl = ssl
	newWF.buffer = buff
	newWF.conn = conn
	newWF.cryptoBuff = cbf.NewCryptoBuff(ssl.lg, conn)
	return &newWF
}

func (wf *wkf) Start() {

	var err error

	wf.ssl.lg.Debugf("Starting handshake with '%v'", wf.conn.RemoteAddr())
	msgHC, err := wf.ssl.ifs.CliHelo.Handle(wf.buffer[ifs.TLS_HANDSHAKE_SIZE:])
	if err != nil {
		wf.ssl.lg.Error("client hello handle:", err)
		return
	}

	// Check TLS version (muste be 1.2[0x0303])
	if binary.BigEndian.Uint16(msgHC.Version[:]) != 0x0303 {
		wf.ssl.lg.Errorf("TLS version not supported: %.4x",
			binary.BigEndian.Uint16(msgHC.Version[:]))
		return
	}

	// Save client hello packet
	wf.cryptoBuff.Set(cbf.CLIENT_HELLO, wf.buffer)

	// server hello message
	err = wf.pktServerHelo(msgHC)
	if err != nil {
		wf.ssl.lg.Error("server hello response packet:", err)
		return
	}

	// Give me the certificate right now
	err = wf.pktCertificate(msgHC)
	if err != nil {
		wf.ssl.lg.Error("certificate packet:", err)
		return
	}

	cct := wf.cryptoBuff.GetCert()
	if cct == nil {
		wf.ssl.lg.Error("cryptobuff has no certificate")
		return
	}

	// Practice ciphering
	wf.practiceCipher()

	/*suite, err := wf.ssl.modz.CipherSuites.GetSuite(
		wf.cryptoBuff.GetCipherSuite())
	if err != nil {
		wf.ssl.lg.Error("suite not found:", err)
		return
	}

	switch suite.KeyExchange {
	case mx.KEY_EXCHANGE_RSA:
		wf.handleClientKeyExchange()

	case mx.KEY_EXCHANGE_DHE:
		wf.ssl.lg.Warn("DHE not implemented yet")

	default:
		wf.ssl.lg.Error("key exchange not supported")
		return
	}

	wf.handleClientKeyExchange()*/
}

func (wf *wkf) handleClientKeyExchange() {

	var err error

	newBuff := make([]byte, 4096)
	wf.pktServerHeloDone()
	err = wf.cryptoBuff.Send(cbf.SERVER_HELLO | cbf.CERTIFICATE |
		cbf.SERVER_HELLO_DONE)

	if err != nil {
		wf.ssl.lg.Error("RSA process send:", err)
		return
	}

	wf.ssl.lg.Info("RSA partial handshake done")

	// Receive client key exchange
	n, err := wf.conn.Read(newBuff)
	if err != nil {
		wf.ssl.lg.Error("RSA process read:", err)
		return
	}

	fmt.Println("Received:", n, "bytes")
	fmt.Println(systema.PrettyPrintBytes(newBuff[:n]))
}

func (wf *wkf) practiceCipher() {

	fmt.Println(wf.ssl.modz.TLSSuite.PrintAll())
}
