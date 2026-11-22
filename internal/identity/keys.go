package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func generateIdentity() (*SoftwareIdentity, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &SoftwareIdentity{
		privateKey: priv,
	}, nil
}

func encodePublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// testing
	fmt.Printf("%s", pubPEM)
	fmt.Println("PKCS#8 DER bytes:", len(pubDER))

	return pubPEM, nil
}

func encodePrivateKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	// testing
	fmt.Printf("%s", privPEM)
	fmt.Println("PKCS#8 DER bytes:", len(privDER))

	return privPEM, nil
}

func (i *SoftwareIdentity) PublicKey() ([]byte, error) {
	return encodePublicKey(&i.privateKey.PublicKey)
}

func (i *SoftwareIdentity) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	signed, err := ecdsa.SignASN1(rand.Reader, i.privateKey, digest[:])
	if err != nil {
		return nil, err
	}

	// testing
	fmt.Println("signature bytes (DER):", len(signed))

	return signed, nil
}

func (i *SoftwareIdentity) verify(msg, signature []byte) bool {
	isValid := false

	digest := sha256.Sum256(msg)
	validKey := ecdsa.VerifyASN1(&i.privateKey.PublicKey, digest[:], signature)

	if validKey == true {
		tamperedMsg := make([]byte, len(msg))
		copy(tamperedMsg, msg)

		if len(tamperedMsg) == 0 {
			return false
		}

		tamperedMsg[0] ^= 1
		tamperedDigest := sha256.Sum256(tamperedMsg)
		isTampered := ecdsa.VerifyASN1(&i.privateKey.PublicKey, tamperedDigest[:], signature)

		if isTampered == false {
			isValid = true
		}
	}

	return isValid
}

func decodePublicKey(data []byte) (*ecdsa.PublicKey, error) {
	// Parse the public key back from PEM
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, errors.New("unexpected PEM block type")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}

	if pub.Curve != elliptic.P256() {
		return nil, errors.New("public key is not P-256")
	}

	return pub, nil
}

func decodePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, errors.New("unexpected PEM block type")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA")
	}

	if priv.Curve != elliptic.P256() {
		return nil, errors.New("private key is not P-256")
	}

	return priv, nil
}
