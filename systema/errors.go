package systema

import (
	"errors"
)

var (
	ErrNilLogger         = errors.New("nil logger")
	ErrNilParams         = errors.New("nil or invalidad parameters")
	ErrInvalidBufferSize = errors.New("invalid buffer size")
	ErrNilController     = errors.New("nil controller/systema")
	ErrAlreadyExists     = errors.New("Object already exists")
	ErrNotFound          = errors.New("Object not found")
	ErrNilModulo         = errors.New("nil modulos/interfaces")
	ErrInvalidConfig     = errors.New("invalid configuration")
	ErrInvalidData       = errors.New("invalid data")
	ErrInvalidType       = errors.New("invalid type")
)
