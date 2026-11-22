package identity

import (
	"crypto/ecdsa"
)

type Identity interface {
	PublicKey() ([]byte, error)
	Sign(message []byte) ([]byte, error)
}

type SoftwareIdentity struct {
	privateKey *ecdsa.PrivateKey
}
