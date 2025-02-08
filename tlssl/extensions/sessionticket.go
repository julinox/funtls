package extensions

type ExtSessionTicketData struct {
}

type xExtSessionTicket struct {
}

func NewExtSessionTicket() Extension {
	return &xExtSessionTicket{}
}

func (x xExtSessionTicket) Name() string {
	return ExtensionName[x.ID()]
}

func (x xExtSessionTicket) ID() uint16 {
	return 0x0023
}

func (x xExtSessionTicket) LoadData(data []byte, sz int) (interface{}, error) {
	return &ExtSessionTicketData{}, nil
}

func (x xExtSessionTicket) PrintRaw(data []byte) string {
	return "0x00 0x23(ExtID) 0x00 0x00(ExtLen)"
}

func (x xExtSessionTicket) PacketServerHelo(data interface{}) ([]byte, error) {
	return []byte{0x00, 0x23, 0x00, 0x00}, nil
}
