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
			{ID: 0x000D, Config: extensions.Config0x00D{ClientWeight: 1, ServerWeight: 2}},
		})

	if err != nil {
		ssl.lg.server.Error("Error initializing extensions: ", err)
		return
	}

	//pp.List()[0].Execute(nil)
	helper(pp.List()[0])
}

func helper(ext extensions.Extension) {

	var numbers = []uint16{
		0x0403,
		0x0503,
		0x0603,
		0x0807,
		0x0808,
		0x0809,
		0x080a,
		0x0501, // rsa_pkcs1_sha384
		0x0805, // rsa_pss_rsae_sha384
		0x0806,
		0x0804, // rsa_pss_rsae_sha256
		0x0401, // rsa_pkcs1_sha256
		0x080b,
		0x0601,
		0x0303,
		0x0301,
		0x0302,
		0x0402,
		0x0502,
		0x0602,
	}

	var numbers2 = []uint16{
		0x0501, // rsa_pkcs1_sha384
		0x0805, // rsa_pss_rsae_sha384
		0x0804, // rsa_pss_rsae_sha256
	}

	if ext == nil {
		return
	}

	if !true {
		ext.Execute(numbers2)
	} else {
		ext.Execute(numbers)
	}
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
