package server

import (
	"tlesio/systema"
	iff "tlesio/tlssl/interfaces"
	mx "tlesio/tlssl/modulos"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

/*type Modulos struct {
	Cert         mx.ModCerts
	CipherSuites mx.ModCipherSuites
}*/

type zzl struct {
	modz mx.ModuloZ
	lg   *logrus.Logger
	ifs  *iff.Interfaces
}

func initTLS() (*zzl, error) {

	var ssl zzl

	ssl.lg = getTLSLogger()
	ssl.initModCerts()
	ssl.initModCipherSuites()
	ssl.initSignAlgo()
	if err := ssl.modz.CheckModInit(); err != nil {
		ssl.lg.Error("error initializing TLS Modules: ", err)
		return nil, err
	}

	ssl.lg.Info("TLS Modules initialized")
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

func (x *zzl) initSignAlgo() {
	x.modz.InitSignAlgo(x.lg)
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
