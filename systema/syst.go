package systema

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
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

func MyName() string {

	pc, file, _, _ := runtime.Caller(1)
	funcAllName := path.Base(runtime.FuncForPC(pc).Name())
	parts := strings.Split(funcAllName, ".")
	funcName := parts[len(parts)-1]
	filename := filepath.Base(file)
	return fmt.Sprintf("%s/%s", funcName, filename)
}

func SASupportAny(mapa map[uint16]bool, lista []uint16) bool {

	if len(mapa) == 0 || len(lista) == 0 {
		return false
	}

	for _, l := range lista {
		if mapa[l] {
			return true
		}
	}

	return false
}

func SASupportFirst(mapa map[uint16]bool, lista []uint16) uint16 {

	if len(mapa) == 0 || len(lista) == 0 {
		return 0
	}

	for _, l := range lista {
		if mapa[l] {
			return l
		}
	}

	return 0
}

// para firmar necesito 2 cosas:
//  1. La funcion hash, que es definida por el schema
//  2. La curva (si es ecdsa), en cuyo caso necesito saber la curva especifica
//     via la public key y tambien necesito la lista SG que debe ser vacia o
//     contener la curva candidata (de la publickey)

func TopoGigio() {

}
