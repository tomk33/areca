package identity

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

func (i *SoftwareIdentity) TLSCertificate() (tls.Certificate, error) {
	now := time.Now()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "Areca"},
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		BasicConstraintsValid: true,

		DNSNames: []string{"areca"}, // every user has a unique crypto key but the cert name is the same (For testing this can be used but later on a cert needs to be trusted by crypto key)
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&i.privateKey.PublicKey,
		i.privateKey,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: i.privateKey, Leaf: parsedCert}, nil
}
