package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"tlesio/systema"
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
		ssl.lg.Error("buffer is too small for a client hello")
		return nil
	}

	newWF.ssl = ssl
	newWF.buffer = buff
	newWF.conn = conn
	newWF.offset = offset
	return &newWF
}

func (wf *wkf) Start() {

	var err error
	var outputBuff []byte

	wf.ssl.lg.Debugf("Starting handshake with '%v'", wf.conn.RemoteAddr())
	msgHC, err := wf.ssl.ifs.CliHelo.Handle(wf.buffer[wf.offset:])
	if err != nil {
		wf.ssl.lg.Error("client hello handle:", err)
		return
	}

	// Check TLS version (muste be 1.0[0x0303])
	if binary.BigEndian.Uint16(msgHC.Version[:]) != 0x0303 {
		wf.ssl.lg.Errorf("TLS version not supported: %.4x",
			binary.BigEndian.Uint16(msgHC.Version[:]))
		return
	}

	// server hello message
	outputBuff, err = wf.pktServerHelo(msgHC)
	if err != nil {
		wf.ssl.lg.Error("server hello response packet:", err)
		return
	}

	// Send it
	err = wf.sendMe(outputBuff)
	if err != nil {
		wf.ssl.lg.Error("error sending response:", err)
		return
	}
}

// Build Server Hello packet message
func (wf *wkf) pktServerHelo(cMsg *ifs.MsgHelloCli) ([]byte, error) {

	var outputBuff []byte

	sMsg, err := wf.ssl.ifs.ServerHelo.Handle(cMsg)
	if err != nil {
		return nil, err
	}

	// Server hello payload
	sHelloBuff := wf.ssl.ifs.ServerHelo.Packet(sMsg)

	// Extensions payload
	extsBuff := wf.ssl.ifs.ServerHelo.PacketExtensions(cMsg)

	// Handshake header
	hsHeaderBuff := wf.ssl.ifs.TLSHead.HandShakePacket(&ifs.TLSHandshake{
		HandshakeType: ifs.HandshakeTypeServerHelo,
		Len:           len(sHelloBuff) + len(extsBuff)})

	// TLS Header
	outputBuff = wf.ssl.ifs.TLSHead.HeaderPacket(&ifs.TLSHeader{
		ContentType: ifs.ContentTypeHandshake,
		Version:     0x0303,
		Len:         len(hsHeaderBuff) + len(sHelloBuff) + len(extsBuff)})

	// Concatenate all buffers
	outputBuff = append(outputBuff, hsHeaderBuff...)
	outputBuff = append(outputBuff, sHelloBuff...)
	outputBuff = append(outputBuff, extsBuff...)
	return outputBuff, nil
}

func (wf *wkf) pktCertificate() []byte {

	return nil
}

func (wf *wkf) sendMe(buffer []byte) error {

	if buffer == nil {
		return systema.ErrNilParams
	}

	if len(buffer) < 42 {
		return fmt.Errorf("buffer is too small to send")
	}

	_, err := wf.conn.Write(buffer)
	if err != nil {
		return err
	}

	return nil
}
