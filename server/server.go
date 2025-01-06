package handshake

import (
	"net"
	"tlesio/tlss"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

const (
	port         = ":8443"
	responseBody = "Hello, TLS!"
)

type zzl struct {
	lg    *logrus.Logger
	tlsLg *logrus.Logger
}

func RealServidor() {

	var ssl zzl

	ssl.lg = clog.InitNewLogger(&clog.CustomFormatter{Tag: "SERVER"})
	ssl.tlsLg = clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	ssl.tlsLg.SetLevel(logrus.DebugLevel)
	listener, err := net.Listen("tcp", port)
	if err != nil {
		panic(err)
	}

	defer listener.Close()
	ssl.lg.Info("Listening on PORT ", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			ssl.lg.Error("Error accepting connection:", err)
			continue
		}

		go ssl.handleConnection(conn)
	}
}

func (ssl *zzl) handleConnection(conn net.Conn) {

	defer conn.Close()
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		ssl.lg.Error("Error reading data:", err)
		return
	}

	if n <= 5 {
		ssl.lg.Warning("Very little Data")
		return
	}

	tlss.TLSMe(buffer[:n], ssl.tlsLg)
}
