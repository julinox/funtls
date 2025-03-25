package server

import (
	"fmt"
	"os"
	"strings"
	ex "tlesio/tlssl/extensions"
	mx "tlesio/tlssl/modulos"
	"tlesio/tlssl/suite"
	"tlesio/tlssl/suite/ciphersuites"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

var (
	_ENV_LOG_LEVEL_VAR_   = "TLS_LOG_LEVEL"
	_ENV_CLIENT_AUTH_VAR_ = "TLS_CLIENT_AUTH"
)

func (x *serverOp) initTLSContext() error {

	x.initTLSContexLg()
	x.initTLSContextModz()
	x.initTLSContextExtensions()
	x.tlsCtx.OptClientAuth = getTLSClientAuthOpt()
	return nil
}

func (x *serverOp) initTLSContexLg() {

	var lvl logrus.Level

	if x.err != nil {
		return
	}

	lg := clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	if lg == nil {
		x.err = fmt.Errorf("logger Init err")
		return
	}

	levelStr := strings.ToUpper(os.Getenv(_ENV_LOG_LEVEL_VAR_))
	switch levelStr {
	case "TRACE":
		lvl = logrus.TraceLevel
	case "DEBUG":
		lvl = logrus.DebugLevel
	case "WARN":
		lvl = logrus.WarnLevel
	case "ERROR":
		lvl = logrus.ErrorLevel
	case "FATAL":
		lvl = logrus.FatalLevel
	case "PANIC":
		lvl = logrus.PanicLevel
	default:
		lvl = logrus.InfoLevel
	}

	lg.SetLevel(lvl)
	x.tlsCtx.Lg = lg
}

func (x *serverOp) initTLSContextModz() {

	certs := []*mx.CertPaths{
		{PathCert: "./certs/server.crt", PathKey: "./certs/server.key"},
		{PathCert: "./certs/server2.crt", PathKey: "./certs/server.key"},
	}

	suites := []suite.Suite{
		ciphersuites.NewAES_256_CBC_SHA(),
		ciphersuites.NewAES_256_CBC_SHA256(),
	}

	if x.err != nil {
		return
	}

	x.tlsCtx.Modz = mx.NewModuloZ()
	x.tlsCtx.Modz.InitTLSSuite(x.tlsCtx.Lg, suites)
	x.tlsCtx.Modz.InitCerts(x.tlsCtx.Lg, certs)
	x.err = x.tlsCtx.Modz.CheckModInit()
}

func (x *serverOp) initTLSContextExtensions() {

	if x.err != nil {
		return
	}

	x.tlsCtx.Exts = ex.NewExtensions(x.tlsCtx.Lg)
	x.tlsCtx.Exts.Register(ex.NewExtSignAlgo())
	x.tlsCtx.Exts.Register(ex.NewExtSessionTicket())
	x.tlsCtx.Exts.Register(ex.NewExtSNI())
	//x.tlsCtx.Exts.Register(ex.NewExtEncryptThenMac())
	x.tlsCtx.Exts.Register(ex.NewExtRenegotiation())
}

func getTLSClientAuthOpt() bool {
	return strings.ToLower(os.Getenv(_ENV_CLIENT_AUTH_VAR_)) == "true"
}
