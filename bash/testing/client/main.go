package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	fmt.Println("Client sending through Areca ...")

	conn, err := net.Dial("udp", "localhost:4433")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	message := []byte("Hello server!")
	_, err = conn.Write(message)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Message sent ...")
}
