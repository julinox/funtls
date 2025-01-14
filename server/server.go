package handshake

import (
	"net"
	"tlesio/tlss"
	"tlesio/tlss/extensions"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

const (
	port         = ":8443"
	responseBody = "Hello, TLS!"
)

type zzl struct {
	lg zzlLoggers
}

type zzlLoggers struct {
	tls    *logrus.Logger
	server *logrus.Logger
}

func RealServidor() {

	var ssl zzl

	ssl.lg.server = clog.InitNewLogger(&clog.CustomFormatter{Tag: "SERVER"})
	ssl.lg.tls = clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	ssl.lg.tls.SetLevel(logrus.InfoLevel)
	ssl.lg.server.Info("Hello little teapot")
	pp, err := extensions.InitExtensions(ssl.lg.tls,
		[]extensions.NewExt{
			{ID: 0x000D, Config: extensions.Config0x00D{ClientWeight: 1, ServerWeight: 30}},
		})

	if err != nil {
		ssl.lg.server.Error("Error initializing extensions: ", err)
		return
	}

	//pp.List()[0].Execute(nil)
	helper(pp.List()[0])
}

func helper(ext extensions.Extension) {

	var numbers = map[uint16]int{
		0x0403: 1,
		0x0503: 2,
		0x0603: 3,
		0x0807: 4,
		0x0808: 5,
		0x0809: 6,
		0x080a: 7,
		0x080b: 8,
		0x0804: 9,
		0x0805: 10,
		0x0806: 11,
		0x0401: 12,
		0x0501: 12 + 1,
		0x0601: 14,
		0x0303: 15,
		0x0301: 16,
		0x0302: 17,
		0x0402: 18,
		0x0502: 19,
		0x0602: 20,
	}

	if ext == nil {
		return
	}

	ext.Execute(numbers)
}

func RealServidor2() {

	var ssl zzl

	ssl.lg.server = clog.InitNewLogger(&clog.CustomFormatter{Tag: "SERVER"})
	ssl.lg.tls = clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	ssl.lg.tls.SetLevel(logrus.DebugLevel)
	listener, err := net.Listen("tcp", port)
	if err != nil {
		panic(err)
	}

	defer listener.Close()
	ssl.lg.server.Info("Listening on PORT ", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			ssl.lg.server.Error("Error accepting connection:", err)
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
		ssl.lg.server.Error("Error reading data:", err)
		return
	}

	if n <= 5 {
		ssl.lg.server.Warning("Very little Data")
		return
	}

	tlss.TLSMe(buffer[:n], ssl.lg.tls)
}
