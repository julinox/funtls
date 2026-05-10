package ftbuffer

import (
	"sync"
)

type PoolBuff struct {
	id    string
	pulpo *sync.Pool
}

func NewPoolBuff(sz uint, id string) *PoolBuff {

	var newPB PoolBuff

	if sz == 0 {
		return nil
	}

	newPB.id = id
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

	x.pulpo.Put(bytes)
}

func (x *PoolBuff) ID() string {
	return x.id
}

func newPBuffer(buffSz uint) *sync.Pool {

	return &sync.Pool{
		New: func() any {
			return make([]byte, 0, buffSz)
		},
	}
}
