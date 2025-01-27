package systema

import (
	"fmt"
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

// Print a byte array in a 'pretty' format
func PrettyPrintBytes(buffer []byte) string {

	var pretty string

	for i, b := range buffer {
		pretty += fmt.Sprintf("%02x ", b)
		if (i+1)%16 == 0 && i+1 != len(buffer) {
			pretty += "\n"
		}
	}

	return pretty
}

func FileExists(path string) bool {

	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
