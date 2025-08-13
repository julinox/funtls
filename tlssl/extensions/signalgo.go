package extensions

import (
	"fmt"

	"github.com/julinox/funtls/tlssl/names"
)

type ExtSignAlgoData struct {
	Len   uint16
	Algos []uint16
}

type xExtSignAlgo struct {
}

func NewExtSignAlgo() Extension {
	return &xExtSignAlgo{}
}

func (x xExtSignAlgo) Name() string {
	return "Signature_Algorithms"
}

func (x xExtSignAlgo) ID() uint16 {
	return 0x000D
}

func (x xExtSignAlgo) LoadData(data []byte, sz int) (interface{}, error) {

	var offset uint16 = 2
	var newData ExtSignAlgoData

	if len(data) < 2 || len(data) != sz || len(data)%2 != 0 {
		return nil, fmt.Errorf("invalid datalen for extension %v", x.Name())
	}

	newData.Len = uint16(data[0])<<8 | uint16(data[1])/2
	if len(data) < int(newData.Len) {
		return nil, fmt.Errorf("data len mismatch for extension %v", x.Name())
	}

	newData.Algos = make([]uint16, 0)
	for i := 0; i < int(newData.Len); i++ {
		newData.Algos = append(newData.Algos,
			uint16(data[offset])<<8|uint16(data[offset+1]))
		offset += 2
	}

	return &newData, nil
}

func (x *xExtSignAlgo) PacketServerHelo(data any) ([]byte, error) {
	return nil, nil
}

func (x xExtSignAlgo) PrintRaw(data []byte) string {

	var length int
	var newStr string = "{"
	var offset uint16 = 2

	if len(data) < 2 || len(data)%2 != 0 {
		return "{}"
	}

	length = int(data[0])<<8 | int(data[1])/2
	if len(data[offset:])/2 != length {
		return "Invalid Data"
	}

	for i := 0; i < length; i++ {
		id := uint16(data[offset])<<8 | uint16(data[offset+1])
		algo := names.SignHashAlgorithms[id]
		if algo == "" {
			algo = "*"
		}

		if i == length-1 {
			newStr += algo
		} else {
			newStr += algo + ","
		}

		offset += 2
	}

	newStr += "}"
	return newStr
}
