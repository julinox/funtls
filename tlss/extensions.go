package tlss

import "fmt"

var extns = map[string]uint16{
	"signature_algorithms": 0x000d,
}

type SignatureAlgorithms struct {
	Size       int
	Algorithms []uint16
}

func NewExtension(buffer []byte) interface{} {

	// buffer should point to the beginning of the extension

	if buffer == nil {
		return nil
	}

	id := uint16(buffer[0])<<8 + uint16(buffer[1])
	switch id {
	case extns["signature_algorithms"]:
		return NewExtensionSignatureAlgorithms(buffer[2:])
	default:
		return nil
	}
}

func NewExtensionSignatureAlgorithms(buffer []byte) *SignatureAlgorithms {

	var sa SignatureAlgorithms

	if buffer == nil {
		return nil
	}

	/*sa.Size = int(buffer[0])<<8 + int(buffer[1])
	sa.Algorithms = make([]uint16, sa.Size/2)

	for i := 0; i < sa.Size; i += 2 {
		sa.Algorithms[i/2] = uint16(buffer[i+2])<<8 + uint16(buffer[i+3])
	}*/

	fmt.Println("MIRA LA SIGNATURA DE ALGORITMOS")
	return &sa
}
