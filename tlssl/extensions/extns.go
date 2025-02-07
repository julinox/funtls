package extensions

var ExtensionName = map[uint16]string{
	0x000D: "signature_algorithms",
}

type ExtLoadFN func([]byte, int) (interface{}, error)

type Extension interface {
	ID() uint16
	Name() string
	PrintRaw([]byte) string
	LoadData([]byte, int) (interface{}, error)
}

type Extensions struct {
	table map[uint16]Extension
}

func NewExtensions() *Extensions {

	var newExtns Extensions

	newExtns.table = make(map[uint16]Extension)
	return &newExtns
}

func (e *Extensions) Add(ext Extension) {

	if ext == nil {
		return
	}

	if _, ok := e.table[ext.ID()]; ok {
		return
	}

	e.table[ext.ID()] = ext
}

func (e *Extensions) Get(id uint16) Extension {

	if ext, ok := e.table[id]; ok {
		return ext
	}

	return nil
}
