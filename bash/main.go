package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
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

	// Create this devices TLS cert
	cert, err := id.TLSCertificate()
	if err != nil {
		return err
	}

	// Load the public key of the device we trust.
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

	// CONTINUE FOR LISTENER AND HANDLING MESSAGES VIA NEW FUNCTION

	return nil
}

func loadPeerPublicKey(path string) ([]byte, error) {

	// CODE FOR GETTING KEY FROM XML HERE

	return // key
}

func createTLSCfg(cert tls.Certificate, peerKey []byte, isServer bool) *tls.Config {

}
