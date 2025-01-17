package handshake

import (
	"net"
	"tlesio/systema"
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
	lg   *logrus.Logger
	ctrl tlss.TLSControl
}

func RealServidor() {

	var ssl zzl
	var err error

	ssl.lg = clog.InitNewLogger(&clog.CustomFormatter{Tag: "SERVER"})
	ssl.ctrl, err = newTLSControl()
	if err != nil {
		ssl.lg.Error("Error creating TLS Control:", err)
		return
	}

	listener, err := net.Listen("tcp", port)
	if err != nil {
		ssl.lg.Error(err)
		return
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

func newTLSControl() (tlss.TLSControl, error) {

	var err error
	var newControl tlss.TLSControl

	newControl = tlss.NewTlsController()
	err = initControlLogger(newControl)
	if err != nil {
		return nil, err
	}

	err = initControlExtensions(newControl)
	if err != nil {
		return nil, err
	}

	return newControl, nil
}

func initControlLogger(ctrl tlss.TLSControl) error {

	if ctrl == nil {
		return systema.ErrNilLogger
	}

	lg := clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	lg.SetLevel(logrus.DebugLevel)
	ctrl.SetLogger(lg)
	return nil
}

func initControlExtensions(ctrl tlss.TLSControl) error {

	var newExts []extensions.NewExt

	// signature_algorithms extension
	ext1 := extensions.NewExt{ID: 0x000D, Config: extensions.Config0x00D{
		ClientWeight: 1, ServerWeight: 2}}
	newExts = append(newExts, ext1)
	exts, err := extensions.InitExtensions(nil, newExts)
	if err != nil {
		return err
	}

	ctrl.SetExtensions(exts)
	return nil
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

	tlss.TLSMe(buffer[:n], nil)
}
