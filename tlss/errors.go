package tlss

import (
	"errors"
)

var (
	ErrNilLogger = errors.New("nil logger")
	ErrNilParams = errors.New("nil or invalidad parameters")
)
