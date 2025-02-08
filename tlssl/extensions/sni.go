package extensions

const _MAX_SNI_NAMES = 5

type ExtSNIName struct {
	NameType uint8
	Name     string
}

type ExtSNIData struct {
	Names []ExtSNIName
}

type xExtSNI struct {
}

func NewExtSNI() Extension {
	return &xExtSNI{}
}

func (x xExtSNI) Name() string {
	return ExtensionName[x.ID()]
}

func (x xExtSNI) ID() uint16 {
	return 0x0000
}

func (x xExtSNI) LoadData(data []byte, sz int) (interface{}, error) {

	var count uint16
	var offset uint16
	var newData ExtSNIData

	newData.Names = make([]ExtSNIName, 0)
	totalSz := uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2
	for offset < totalSz {
		newName, sz := parseName(data[offset:])
		if newName != nil {
			newData.Names = append(newData.Names, *newName)
		}

		offset += sz
		count++
		// Security measure
		if count > _MAX_SNI_NAMES {
			break
		}
	}

	return &newData, nil
}

func (x xExtSNI) PrintRaw(data []byte) string {

	return ""
}

func (x xExtSNI) PacketServerHelo(data interface{}) ([]byte, error) {
	return nil, nil
}

func parseName(buff []byte) (*ExtSNIName, uint16) {

	var offset uint16
	var newName ExtSNIName

	newName.NameType = uint8(buff[0])
	nameLen := uint16(buff[1])<<8 | uint16(buff[2])
	if len(buff) < int(nameLen) {
		return nil, 0
	}

	offset = 3
	newName.Name = string(buff[offset : offset+nameLen])
	offset += nameLen
	return &newName, offset

}
