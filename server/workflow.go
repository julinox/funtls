package server

import (
	"encoding/binary"
	"net"
	ifs "tlesio/tlssl/interfaces"
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
	pkt := wf.sayHelloBack(msgHC)
	wf.conn.Write(pkt)
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
