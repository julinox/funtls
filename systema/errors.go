package systema

import (
	"errors"
)

var (
	ErrNilLogger         = errors.New("nil logger")
	ErrNilParams         = errors.New("nil or invalidad parameters")
	ErrInvalidBufferSize = errors.New("invalid buffer size")
)
