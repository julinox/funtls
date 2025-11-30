package keyexchange

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"fmt"
	"math/big"

	"github.com/julinox/funtls/tlssl/names"
)

const (
	SKE_POLICY_PERFORMANCE = iota + 1
	SKE_POLICY_SECURITY
)

const (
	SKE_ALGORITHM_DHE = iota + 1
	SKE_ALGORITHM_ECDHE
)

const _DEFAULT_ECDHE_GROUP = names.SECP256R1

type xEcdhe struct {
	group uint16
	x     *big.Int
	y     *big.Int
	curva elliptic.Curve
}

type xDhe struct {
}
type KXParamsOpts struct {
	Policy    int
	Algorithm int
	SG        []uint16
	SA        []uint16
}

type KXParams struct {
	priv  []byte
	dhe   *xDhe
	ecdhe *xEcdhe
	opts  *KXParamsOpts
}

func KeyExchangeParams(opts *KXParamsOpts) (*KXParams, error) {

	if opts == nil {
		return nil, fmt.Errorf("nil params")
	}

	switch opts.Algorithm {
	case SKE_ALGORITHM_DHE:
		return nil, fmt.Errorf("not implemented kx_dhe")

	case SKE_ALGORITHM_ECDHE:
		return kxEcdhe(opts)
	}

	return nil, fmt.Errorf("unknow KX algorithm")
}

func kxEcdhe(opts *KXParamsOpts) (*KXParams, error) {

	var err error
	var params KXParams

	if opts == nil {
		return nil, fmt.Errorf("nil params")
	}

	params.ecdhe, err = selectCurva(opts.Policy, opts.SG)
	if err != nil {
		return nil, err
	}

	priv, x, y, err := elliptic.GenerateKey(params.ecdhe.curva, crand.Reader)
	if err != nil {
		return nil, err
	}

	params.priv = priv
	params.ecdhe.x = x
	params.ecdhe.y = y
	return &params, nil
}

func selectCurva(policy int, sg []uint16) (*xEcdhe, error) {

	var curva uint16
	var curvas []uint16

	if len(sg) == 0 {
		return &xEcdhe{
			group: _DEFAULT_ECDHE_GROUP,
			curva: eliptica(_DEFAULT_ECDHE_GROUP),
		}, nil
	}

	for _, group := range sg {
		if eliptica(group) != nil {
			curvas = append(curvas, group)
		}
	}

	if len(curvas) == 0 {
		return nil, fmt.Errorf("no compatible curves on SG list")
	}

	switch policy {
	case SKE_POLICY_PERFORMANCE:
		curva = curvas[0]
		for _, c := range curvas {
			if c < curva {
				curva = c
			}
		}

	case SKE_POLICY_SECURITY:
		n, _ := crand.Int(crand.Reader, big.NewInt(int64(len(curvas))))
		curva = curvas[int(n.Int64())]

	default:
		return nil, fmt.Errorf("unknow KX group choose policy")
	}

	return &xEcdhe{
		group: curva,
		curva: eliptica(curva),
	}, nil
}

func eliptica(group uint16) elliptic.Curve {

	switch group {
	case names.SECP256R1:
		return elliptic.P256()
	case names.SECP384R1:
		return elliptic.P384()
	case names.SECP521R1:
		return elliptic.P521()
	default:
		return nil
	}
}
