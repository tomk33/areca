package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/tomk33/areca/internal/database"
	"github.com/tomk33/areca/internal/identity"
)

func main() {
	// Getting values from user entry (later implemented inside system and a user click on a device name)
	listenAddr := flag.String("listen", ":4433", "")
	peerAddr := flag.String("peer", "", "")
	peerKeyPath := flag.String("peer-key", "", "")

	flag.Parse()

	run(*listenAddr, *peerAddr, *peerKeyPath)
}

func run(listenAddr, peerAddr, peerKeyPath string) error {
	fmt.Println("Starting Areca...")

	// Load this devices persistent id
	id, err := identity.LoadOrCreate()
	if err != nil {
		return err
	}

	// Load or create the device's db info
	device, err := database.LoadOrCreateDevice()
	if err != nil {
		return err
	}

	// Register only if this device has not been registered yet
	if device.Username == "" {
		err = database.RegisterDevice(id, device)
		if err != nil {
			return err
		}
	}

	// Create this devices TLS cert
	cert, err := id.TLSCertificate()
	if err != nil {
		return err
	}

	// Load the public key of the device we trust
	peerKey, err := loadPeerPublicKey(peerKeyPath)
	if err != nil {
		return err
	}

	// Create the TLS configs
	serverTLS := createTLSCfg(cert, peerKey, true)
	clientTLS := createTLSCfg(cert, peerKey, false)

	quicCfg := &quic.Config{}

	// Create the UDP socket for incoming
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	// Create the QUIC transport and listener
	tr := &quic.Transport{
		Conn: udpConn,
	}

	listener, err := tr.Listen(serverTLS, quicCfg)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Println("Listening on port: ", listenAddr)

	// Accept an incoming conn
	incoming := make(chan *quic.Conn, 1)
	acceptErrors := make(chan error, 1)

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				acceptErrors <- err
				return
			}

			incoming <- conn
		}
	}()

	// CONITNUE HERE WITH THE MESSAGING SERVICE......

	return nil
}

func loadPeerPublicKey(path string) ([]byte, error) {
	// CODE FOR GETTING KEY FROM XML HERE

	rawPem, _ := os.ReadFile("./testingKeys/public.key")
	pemBlock, _ := pem.Decode(rawPem)
	publicKey, _ := x509.ParsePKCS1PublicKey(pemBlock.Bytes)

	return publicKey, nil
	// data, err := os.ReadFile(path)
	// if err != nil {
	// 	return nil, err
	// }

	// // Decode the key from the pem format
	// block, _ := pem.Decode(data)
	// if block == nil || block.Type != "PUBLIC KEY" {
	// 	return nil, errors.New("invalid peer public key PEM")
	// }

	// // Parse the block into public key format (.crt)
	// _, err = x509.ParsePKIXPublicKey(block.Bytes)
	// if err != nil {
	// 	return nil, err
	// }
}

func createTLSCfg(cert tls.Certificate, peerKey []byte, isServer bool) *tls.Config {
	// Configure the TLS cert based on either server of client
	tlsCfg := &tls.Config{
		// InsecureSkipVerify: true, // testing only
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPeer(state, peerKey)
		},
	}

	if isServer == true {
		tlsCfg.ClientAuth = tls.RequireAnyClientCert
	} else {
		tlsCfg.InsecureSkipVerify = true
	}

	return tlsCfg
}

// Checks that the presented cert belongs to the trusted device
func verifyPeer(state tls.ConnectionState, peerKey []byte) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("peer did not present a certificate")
	}

	cert := state.PeerCertificates[0]

	// Check that the cert is the expected public key
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, peerKey) {
		return errors.New("peer public key does not match trusted device")
	}

	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return errors.New("peer certificate has expired or is not yet valid")
	}

	// Ensure the cert can be used for digital signatures
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("peer certificate does not permit digital signatures")
	}

	// Verify the certs self signature
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return errors.New("invalid peer certificate signature")
	}

	return nil
}
