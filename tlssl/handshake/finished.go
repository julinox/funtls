package handshake

type xFinished struct {
}

func NewFinished() Finished {
	return &xFinished{}
}

func (x *xFinished) Name() string {
	return "_Finished_"
}

func (x *xFinished) Next() (int, error) {
	return 0, nil
}

func (x *xFinished) Handle(data []byte) error {
	return nil
}
