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
type TheKeyMaker interface {
	//Keys([]byte, []byte, []byte) *SessionKeys
	//PRF([]byte, []byte, []byte, string) []byte
	MasterSecret([]byte, []byte, []byte) []byte
}

//master_secret = PRF(pre_master_secret, "master secret",ClientHello.random + ServerHello.random)
