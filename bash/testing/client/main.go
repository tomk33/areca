package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"github.com/quic-go/quic-go"
	"github.com/tomk33/areca/internal/identity"
)

func main() {
	caCert, _ := os.ReadFile("ca.crt")
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	id, err := identity.LoadOrCreate()
	if err != nil {
		log.Fatal(err)
	}

	cert, err := id.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}

	// Configure TLS
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // testing only
		Certificates:       []tls.Certificate{cert},
		ClientCAs:          caPool,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		MinVersion:         tls.VersionTLS13,
	}

	// Configure QUIC
	quicConf := &quic.Config{}

	conn, err := quic.DialAddr(context.Background(), "localhost:4433", tlsCfg, quicConf)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.CloseWithError(0, "Error connecting to server")

	str, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	message := "Hello from client\n"
	_, err = str.Write([]byte(message))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Message sent")

	// Read response
	response, err := bufio.NewReader(str).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Server response: ", response)

	str.Close()

	// // QUIC listener
	// ln, err := tr.Listen(tlsConf, quicConf)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println("Listening on port 4433")
	// for {
	// 	conn, err := ln.Accept(context.Background())
	// 	if err != nil {
	// 		log.Println("Error accepting connection: ", err)
	// 		continue
	// 	}

	// 	// Handle connection in new go routine
	// 	go handleConn(conn)
	// }
}
