package server

import (
	"encoding/binary"
	"fmt"
	"net"
	ifs "tlesio/tlssl/interfaces"
	mx "tlesio/tlssl/modulos"
)

type wkf struct {
	ssl    *zzl
	buffer []byte
	conn   net.Conn
	offset uint32
}

// Handle Handshake Request
func TLSMe(ssl *zzl, buff []byte, conn net.Conn, offset uint32) *wkf {

	var newWF wkf

	if ssl == nil || buff == nil || conn == nil {
		return nil
	}

	if len(buff) <= 45 {
		ssl.lg.Error("Buffer is too small for a client hello")
		return nil
	}

	newWF.ssl = ssl
	newWF.buffer = buff
	newWF.conn = conn
	newWF.offset = offset
	return &newWF
}

func (wf *wkf) Start() {

	wf.ssl.lg.Debugf("Starting handshake with '%v'", wf.conn.RemoteAddr())
	msgHC, err := wf.ssl.ifs.CliHelo.Handle(wf.buffer[wf.offset:])
	if err != nil {
		wf.ssl.lg.Error("Error handling client hello:", err)
		return
	}

	// Check TLS version (muste be 1.0[0x0303])
	if binary.BigEndian.Uint16(msgHC.Version[:]) != 0x0303 {
		wf.ssl.lg.Errorf("TLS version not supported: %.4x",
			binary.BigEndian.Uint16(msgHC.Version[:]))
		return
	}

	// Prepare buffer with server hello message
	//pkt := wf.sayHelloBack(msgHC)
	wf.sayHelloBack(msgHC)
	//wf.conn.Write(pkt)
	/*modCert := wf.ssl.mods.Get(0xFFFE)
	if modCert == nil {
		wf.ssl.lg.Error("Error getting certificate module")
		return
	}*/

	// Get certificate
	//certs, err := modCert.Handle(nil)
	wf.hereIsMyCert(msgHC)
	wf.ssl.lg.Debug("Server Hello sent")
	//fmt.Println(systema.PrettyPrintBytes(pkt))
	// Pick certificate
}

// Build Server Hello packet message
func (wf *wkf) sayHelloBack(cMsg *ifs.MsgHelloCli) []byte {

	var outputBuff []byte

	sMsg, err := wf.ssl.ifs.ServerHelo.Handle(cMsg)
	if err != nil {
		wf.ssl.lg.Error("Error handling server hello:", err)
		return nil
	}

	// Server hello payload
	buff3 := wf.ssl.ifs.ServerHelo.Packet(sMsg)

	// Extensions payload (none for now!)
	buff2 := wf.addExtensions()

	// Handshake header
	buff1 := wf.ssl.ifs.TLSHead.HandShakePacket(&ifs.TLSHandshake{
		HandshakeType: ifs.HandshakeTypeServerHelo,
		Len:           len(buff3) + len(buff2)})

	// TLS Header
	outputBuff = wf.ssl.ifs.TLSHead.HeaderPacket(&ifs.TLSHeader{
		ContentType: ifs.ContentTypeHandshake,
		Version:     0x0303,
		Len:         len(buff3) + len(buff2) + len(buff1)})

	// Concatenate all buffers
	outputBuff = append(outputBuff, buff1...)
	outputBuff = append(outputBuff, buff2...)
	outputBuff = append(outputBuff, buff3...)
	return outputBuff
}

func (wf *wkf) addExtensions() []byte {
	return nil
}

// Build Certificate packet message
func (wf *wkf) hereIsMyCert(cMsg *ifs.MsgHelloCli) []byte {

	var chosenCert *mx.CertificatesData

	modCerts := wf.ssl.mods.Get(0xFFFE)
	if modCerts == nil {
		wf.ssl.lg.Error("Error getting signature algorithm module")
		return nil
	}

	data := cMsg.Extensions[0x000D]
	// Get first certificate in the list
	if data == nil {
		modCerts.Execute(nil)
		return nil
	}

	dtt, ok := data.(*mx.SignAlgoData)
	if !ok {
		wf.ssl.lg.Error("[hereIsMyCert] error casting SignAlgoData")
		return nil
	}

	//fmt.Println(mx.AlgosToName(0x000d, dtt.Algos))
	for i := 0; i < int(dtt.Len); i++ {
		aux := modCerts.Execute(dtt.Algos[i])
		if aux == nil {
			continue
		}

		chosenCert, ok = aux.(*mx.CertificatesData)
		if !ok {
			wf.ssl.lg.Warn("Error casting CertificatesData")
			continue
		}

	}

	if chosenCert == nil {
		wf.ssl.lg.Error("No certificate found")
		return nil
	}

	fmt.Println(chosenCert)
	return nil
}
