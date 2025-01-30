package server

import "fmt"

type wkf struct {
	buffer []byte
}

func NewWorkflow(buffer []byte) error {

	if buffer == nil || len(buffer) <= 40 {
		return fmt.Errorf("Buffer is nil or too short")
	}

	return nil
}
