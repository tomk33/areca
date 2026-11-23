package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/quic-go/quic-go"

	"github.com/tomk33/areca/internal/identity"
)

type HostProperties struct {
	XMLName xml.Name `xml:"userdb"`
	Users   []User   `xml:"user"`
}

type User struct {
	ID       string   `xml:"id,attr"`
	Username string   `xml:"username"`
	Devices  []Device `xml:"devices>device"`
}

type Device struct {
	ID        string `xml:"id,attr"`
	PublicKey string `xml:"publickey"`
}

func main() {
	fmt.Println("Starting Areca ...")

	caPool := x509.NewCertPool()

	file, err := os.Open("users.xml")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	host := new(HostProperties)

	decoder := xml.NewDecoder(file)
	err = decoder.Decode(host)
	if err != nil {
		log.Fatal(err)
	}

	for _, user := range host.Users {
		fmt.Println("User:", user.Username)

		for _, device := range user.Devices {
			fmt.Println("Device:", device.ID)
			fmt.Println("Public key:", device.PublicKey)
		}
	}

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
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // testing only
		Certificates:       []tls.Certificate{cert},
		ClientCAs:          caPool,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		MinVersion:         tls.VersionTLS13,
	}

	// Configure QUIC
	quicCfg := &quic.Config{}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 4433})
	if err != nil {
		log.Fatal(err)
	}
	defer udpConn.Close()

	tr := quic.Transport{
		Conn: udpConn,
	}

	// QUIC listener
	ln, err := tr.Listen(tlsCfg, quicCfg)
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
		log.Println("Error reading message: ", err)
		return
	}

	fmt.Println("Received:", msg)

	_, err = str.Write([]byte("Hello from the server\n"))
	if err != nil {
		log.Println("Error sending return message: ", err)
	}

	// Close message stream
	str.Close()

	// Wait for connection to close
	<-conn.Context().Done()

	fmt.Println("Connection closed: ", conn.RemoteAddr())
}
