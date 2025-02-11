package extensions

type ExtRenegotiationData struct {
}

type xExtRenegotiation struct {
}

func NewExtRenegotiation() Extension {
	return &xExtRenegotiation{}
}

func (x xExtRenegotiation) Name() string {
	return ExtensionName[x.ID()]
}

func (x xExtRenegotiation) ID() uint16 {
	return 0xFF01
}

func (x xExtRenegotiation) LoadData(data []byte, sz int) (interface{}, error) {
	return &ExtRenegotiationData{}, nil
}

func (x xExtRenegotiation) PrintRaw(data []byte) string {
	return "0xFF 0x01(ExtID) 0x00 0x00(ExtLen)"
}

func (x xExtRenegotiation) PacketServerHelo(data interface{}) ([]byte, error) {
	return []byte{0xFF, 0x01, 0x00, 0x01, 0x00}, nil
}
