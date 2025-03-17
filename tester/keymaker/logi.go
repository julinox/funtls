package keymaker

import (
	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Logger {
	lg := clog.InitNewLogger(&clog.CustomFormatter{Tag: "TESTER"})
	lg.SetLevel(logrus.InfoLevel)
	return lg
}
