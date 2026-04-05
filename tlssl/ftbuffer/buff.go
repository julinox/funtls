package ftbuffer

import (
	"fmt"
	"sync"
)

type PoolBuff struct {
	pulpo *sync.Pool
}

func NewPoolBuff(sz uint) *PoolBuff {

	var newPB PoolBuff

	if sz == 0 {
		return nil
	}

	newPB.pulpo = newPBuffer(sz)
	return &newPB
}

func (x *PoolBuff) Get() []byte {

	bytes, ok := x.pulpo.Get().([]byte)
	if !ok {
		return nil
	}

	return bytes
}

func (x *PoolBuff) Put(bytes []byte) {

	for i := range bytes {
		fmt.Println("i=", i)
		bytes[i] = 0
	}

	x.pulpo.Put(bytes)
}

func newPBuffer(buffSz uint) *sync.Pool {

	return &sync.Pool{
		New: func() any {
			return make([]byte, 0, buffSz)
		},
	}
}
