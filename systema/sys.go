package systema

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func GetLogLevel(envName string) logrus.Level {

	levelStr := strings.ToUpper(os.Getenv(strings.ToUpper(envName)))
	switch levelStr {
	case "TRACE":
		return logrus.TraceLevel
	case "DEBUG":
		return logrus.DebugLevel
	case "WARN":
		return logrus.WarnLevel
	case "ERROR":
		return logrus.ErrorLevel
	case "FATAL":
		return logrus.FatalLevel
	case "PANIC":
		return logrus.PanicLevel
	default:
		return logrus.InfoLevel
	}
}
