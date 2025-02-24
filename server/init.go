package server

import (
	"os"
	"strings"
	ex "tlesio/tlssl/extensions"
	iff "tlesio/tlssl/interfaces"
	mx "tlesio/tlssl/modulos"
	sts "tlesio/tlssl/suites"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

var (
	_ENV_LOG_LEVEL_VAR_   = "TLS_LOG_LEVEL"
	_ENV_CLIENT_AUTH_VAR_ = "TLS_CLIENT_AUTH"
)

type zzl struct {
	modz       *mx.ModuloZ
	lg         *logrus.Logger
	ifs        *iff.Interfaces
	exts       *ex.Extensions
	clientAuth bool // Enable Client Authentication
}

func initTLS() (*zzl, error) {

	var ssl zzl
	var err error

	ssl.lg = getTLSLogger()
	ssl.modz = mx.NewModuloZ()
	if err = ssl.initModuloZ(); err != nil {
		ssl.lg.Error("error initializing TLS Modules: ", err)
		return nil, err
	}

	ssl.exts = ex.NewExtensions(ssl.lg)
	ssl.initExtensions()
	ssl.ifs = iff.InitInterfaces(
		&iff.IfaceParams{
			Lg: ssl.lg, Mx: ssl.modz, Ex: ssl.exts,
		},
	)

	ssl.clientAuth = getTLSClientAuthOpt()
	if ssl.ifs == nil {
		ssl.lg.Error("error initializing TLS Interfaces")
		return nil, err
	}

	ssl.lg.Info("TLS Ready")
	return &ssl, nil
}

func (x *zzl) initModuloZ() error {

	certs := []*mx.CertPaths{
		{PathCert: "./certs/server.crt", PathKey: "./certs/server.key"},
		{PathCert: "./certs/server2.crt", PathKey: "./certs/server.key"},
	}

	suites := []sts.Suite{
		sts.NewAES_256_CBC_SHA256(x.lg),
	}

	x.modz.InitTLSSuite(x.lg, suites)
	x.modz.InitCerts(x.lg, certs)
	return x.modz.CheckModInit()
}

func (x *zzl) initExtensions() {

	x.exts.Register(ex.NewExtSignAlgo())
	x.exts.Register(ex.NewExtSessionTicket())
	x.exts.Register(ex.NewExtSNI())
	x.exts.Register(ex.NewExtEncryptThenMac())
	x.exts.Register(ex.NewExtRenegotiation())
}

func getTLSLogger() *logrus.Logger {

	var lvl logrus.Level

	lg := clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	if lg == nil {
		return nil
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
	return lg
}

func getTLSClientAuthOpt() bool {
	return os.Getenv(_ENV_CLIENT_AUTH_VAR_) == "true"
}
