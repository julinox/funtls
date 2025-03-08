package suite

type Keys struct {
	MAC []byte
	Key []byte
	IV  []byte
}

type SessionKeys struct {
	ClientKeys Keys
	ServerKeys Keys
}

/*type PRFParams struct {
	Label           string
	ClientRandom    []byte
	ServerRandom    []byte
	PreMasterSecret []byte
}*/

type TheKeyMaker interface {
	//Keys([]byte, []byte, []byte) *SessionKeys
	PRF([]byte, []byte, int) []byte
	//MasterSecret([]byte, []byte, []byte) []byte
}

type xKeyMake struct {
	hashAlgo int
}

// All lens in bytes
func NewKeymaker(hashingAlgorithm int) TheKeyMaker {

	if hashingAlgorithm == 0 {
		return nil
	}

	return &xKeyMake{
		hashAlgo: hashingAlgorithm,
	}
}

// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
// A(0) = seed
// A(i) = HMAC_hash(secret, A(i-1))
func (x *xKeyMake) PRF(secret, seed []byte, length int) []byte {

	if secret == nil || seed == nil {
		return nil
	}

	switch x.hashAlgo {
	case SHA256:
		return x.sha256(secret, seed, length)
	}

	return nil
}

func (x *xKeyMake) sha256(secret, seed []byte, length int) []byte {
	return nil
}

//block = PRF(secret,"key expansion"+server_random + client_random);
//master_secret = PRF(pre_master_secret, "master secret" + client_random + Server_random)
