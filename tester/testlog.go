package tester

import (
	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

func TestLogger(lvl logrus.Level) *logrus.Logger {

	lg := clog.InitNewLogger(&clog.CustomFormatter{Tag: "TESTER"})
	lg.SetLevel(lvl)
	return lg
}
