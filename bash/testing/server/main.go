package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/quic-go/quic-go"

	"github.com/tomk33/areca/internal/identity"
)

func main() {
	fmt.Println("Starting Areca ...")

	// Load TLS cert and private key (already created for local testing later different approach)
	// cert, err := tls.LoadX509KeyPair("/server.crt", "/server.key")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	id, err := identity.LoadOrCreate()
	if err != nil {
		log.Fatal(err)
	}

	// testing
	// pub, err := id.PublicKey()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Printf("Identity public key: %x", pub)

	cert, err := id.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}

	// Configure TLS
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Configure QUIC
	quicConf := &quic.Config{}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 4433})
	if err != nil {
		log.Fatal(err)
	}
	defer udpConn.Close()

	tr := quic.Transport{
		Conn: udpConn,
	}

	// QUIC listener
	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Listening on port 4433")
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Println("Error accepting connection: ", err)
			continue
		}

		// Handle connection in new go routine
		go handleConn(conn)
	}
}

func handleConn(conn *quic.Conn) {
	fmt.Println("New connection from: ", conn.RemoteAddr())

	str, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Println("Error accepting stream: ", err)
		return
	}

	msg, err := bufio.NewReader(str).ReadString('\n')
	if err != nil {
		log.Println("Error reading message :", err)
		return
	}

	fmt.Println("Received:", msg)

	_, err = str.Write([]byte("Hello from the receiver.\n"))
	if err != nil {
		log.Println("Error sending return message: ", err)
	}

	// Close message stream
	str.Close()

	// Wait for connection to close
	<-conn.Context().Done()

	fmt.Println("Connection closed: ", conn.RemoteAddr())
}
