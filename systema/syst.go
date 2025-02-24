package systema

import (
	"fmt"
	"os"
)

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

func Uint24(n int) []byte {
	return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
}
