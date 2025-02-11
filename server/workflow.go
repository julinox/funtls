package server

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"time"
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

	switch cct.PublicKeyAlgorithm {
	case x509.RSA:
		wf.rsaMe()
	default:
		wf.ssl.lg.Warnf("Public key algorithm not supported")
	}
}

func (wf *wkf) rsaMe() {

	wf.pktServerHeloDone()
	err := wf.cryptoBuff.Send(cbf.SERVER_HELLO | cbf.CERTIFICATE |
		cbf.SERVER_HELLO_DONE)
	fmt.Println("ERR? ->", err)
	time.Sleep(400 * time.Millisecond)
}
