package server

import (
	"tlesio/systema"
	ex "tlesio/tlssl/extensions"
	iff "tlesio/tlssl/interfaces"
	mx "tlesio/tlssl/modulos"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

type zzl struct {
	modz *mx.ModuloZ
	lg   *logrus.Logger
	ifs  *iff.Interfaces
	exts *ex.Extensions
}

func initTLS() (*zzl, error) {

	var ssl zzl
	var err error

	ssl.lg = getTLSLogger()
	ssl.modz = mx.NewModuloZ()
	ssl.initModCerts()
	ssl.initModCipherSuites()
	if err = ssl.modz.CheckModInit(); err != nil {
		ssl.lg.Error("error initializing TLS Modules: ", err)
		return nil, err
	}

	ssl.exts, err = ex.NewExtensions(ssl.lg)
	if err != nil {
		ssl.lg.Error("error initializing TLS Extensions: ", err)
		return nil, err
	}

	ssl.ifs, err = iff.InitInterfaces(&iff.IfaceParams{
		Lg: ssl.lg, Mx: ssl.modz, Ex: ssl.exts})
	if err != nil {
		ssl.lg.Error("error initializing TLS Interfaces: ", err)
		return nil, err
	}

	ssl.lg.Info("TLS Ready")
	return &ssl, nil
}

func (x *zzl) initModCerts() {

	certs := []*mx.CertPaths{
		{PathCert: "./certs/server.crt", PathKey: "./certs/server.key"},
		{PathCert: "./certs/server2.crt", PathKey: "./certs/server.key"},
	}

	x.modz.InitCerts(x.lg, certs)
}

func (x *zzl) initModCipherSuites() {

	conf := &mx.CipherSuiteConfig{
		ClientWeight: 1,
		ServerWeight: 2,
		Lg:           x.lg,
	}

	x.modz.InitCipherSuites(conf)
}

func getTLSLogger() *logrus.Logger {

	lg := clog.InitNewLogger(&clog.CustomFormatter{
		Tag: "TLS", TagColor: "blue"})
	if lg == nil {
		return nil
	}

	lg.SetLevel(systema.GetLogLevel(_ENV_LOG_LEVEL_VAR_))
	return lg
}
