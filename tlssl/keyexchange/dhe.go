package keyexchange

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/julinox/funtls/systema"
	pki "github.com/julinox/funtls/tlssl/certpki"
	"github.com/julinox/funtls/tlssl/names"
)

type xDHE struct {
	private []byte
	public  []byte
	group   uint16
	sa      []uint16
	sg      []uint16
	gInfo   ffdhegroup
}

func DHEphemeral(sgs, sas []uint16) (KeyExchange, error) {

	var newKE xDHE

	for _, sg := range sgs {
		if !ffdhegroups[sg].enable {
			continue
		}

		newKE.group = sg
		break
	}

	if newKE.group == 0 {
		newKE.group = _DEFAULT_DHE_GROUP
	}

	newKE.gInfo = ffdhegroups[newKE.group]
	pv, err := privateValue(newKE.gInfo.q)
	if err != nil {
		return nil, err
	}

	if len(pv) == 0 {
		return nil, fmt.Errorf("private value was zero")
	}

	newKE.private = pv
	newKE.sa = sas
	newKE.sg = sgs
	newKE.public = publicValue(newKE.gInfo.p, newKE.gInfo.g, newKE.private)
	return &newKE, nil
}

// RFC 7919 demands 1 < peer < p-1
func (x *xDHE) SharedSecret(peer []byte) ([]byte, error) {

	pInt := new(big.Int).SetBytes(x.gInfo.p)
	peerInt := new(big.Int).SetBytes(peer)
	privInt := new(big.Int).SetBytes(x.private)
	one := big.NewInt(1)
	pm1 := new(big.Int).Sub(pInt, one)
	if peerInt.Cmp(one) <= 0 || peerInt.Cmp(pm1) >= 0 {
		return nil, fmt.Errorf("invalid peer value")
	}

	return new(big.Int).Exp(peerInt, privInt, pInt).Bytes(), nil
}

// p len(2B) | p bytes | g len(2B) | g bytes | pub len | pub bytes
func (x *xDHE) Params() []byte {

	var buffer []byte

	buffLen := 2 + len(x.gInfo.p) + 2 + len(x.gInfo.g) + 2 + len(x.public)
	buffer = make([]byte, 0, buffLen)
	buffer = binary.BigEndian.AppendUint16(buffer, uint16(len(x.gInfo.p)))
	buffer = append(buffer, x.gInfo.p...)
	buffer = binary.BigEndian.AppendUint16(buffer, uint16(len(x.gInfo.g)))
	buffer = append(buffer, x.gInfo.g...)
	buffer = binary.BigEndian.AppendUint16(buffer, uint16(len(x.public)))
	buffer = append(buffer, x.public...)
	return buffer
}

func (x *xDHE) Public() []byte {
	return x.public
}

func (x *xDHE) Sign(fp []byte, cpki pki.CertPKI) ([]byte, error) {

	if len(fp) == 0 || cpki == nil {
		return nil, fmt.Errorf("nil fingerpint/certpki")
	}

	certo := cpki.Get(fp)
	if len(certo) == 0 {
		return nil, fmt.Errorf("no certificate match")
	}

	scheme := systema.SASupportFirst(cpki.GetSaSupport(fp), x.sa)
	fmt.Println(names.SignatureAlgorithms[scheme])
	return nil, nil
}

func (x *xDHE) GroupName() string {
	return names.SupportedGroups[x.group]
}

// DH algorithm requires private to be [2,q-1]
// crand.Int(ior, ub) -> [0, ub) = [0,ub-1]. We must add 2 to compensate
// the lower bound, and substract 2 from upper band to avoid overflow:
// 2 + crand.Int(ior, ub-2) -> 2 + [0,ub-3] = [0+2, (ub-3)+2] = [2,ub-1]
func privateValue(qq []byte) ([]byte, error) {

	q := new(big.Int).SetBytes(qq)
	top := new(big.Int).Sub(q, big.NewInt(2))
	if top.Sign() <= 0 {
		return nil, fmt.Errorf("q is too small")
	}

	x, err := rand.Int(rand.Reader, top)
	if err != nil {
		return nil, err
	}

	priv := x.Add(x, big.NewInt(2))
	return priv.Bytes(), nil
}

// "Magical DH" -> public = g^private mod p
func publicValue(p, g, private []byte) []byte {

	pInt := new(big.Int).SetBytes(p)
	gInt := new(big.Int).SetBytes(g)
	xInt := new(big.Int).SetBytes(private)
	return new(big.Int).Exp(gInt, xInt, pInt).Bytes()
}
