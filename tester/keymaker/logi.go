package keymaker

import (
	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

func TestLogger() *logrus.Logger {
	lg := clog.InitNewLogger(&clog.CustomFormatter{Tag: "TESTER"})
	lg.SetLevel(logrus.InfoLevel)
	return lg
}
