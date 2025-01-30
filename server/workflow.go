package server

import (
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

	_, err = wf.ssl.ifs.ServerHelo.Handle(msgHC)
	if err != nil {
		wf.ssl.lg.Error("Error handling server hello:", err)
		return
	}

	// Pick certificate
	pp := ifs.TLSHeader{ContentType: ifs.ContentTypeHandshake, Len: 512}
	fmt.Println(systema.PrettyPrintBytes(wf.ssl.ifs.TLSHead.Packet(&pp)))
}
