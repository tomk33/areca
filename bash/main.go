package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/quic-go/quic-go"
)

func main() {
	fmt.Println("Starting Areca ...")

	// Load TLS cert and private key (already created for local testing later different approach)
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
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

		// handle connection in new go routine
		go handleConn(conn)
	}
}

func handleConn(conn *quic.Conn) {
	fmt.Println("New connection from: ", conn.RemoteAddr())

	<-conn.Context().Done()

	fmt.Println("Connection closed: ", conn.RemoteAddr())
}
