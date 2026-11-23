package main

import (
	"flag"
)

func main() {
	// Getting values from user entry (later implemented inside system and a user click on a device name)
	listenAddr := flag.String("listen", ":4433", "Address to listen on ")
	peerAddr := flag.String("peer", "", "Address of the device to connect to ")
	peerKeyPath := flag.String("peer-key", "", "Path to the peer's public key PEM")

	flag.Parse()

	run(*listenAddr, *peerAddr, *peerKeyPath)
}

func run(listenAddr, peerAddr, peerKeyPath string) error {

	// BEGIN HERE ...

	return nil
}
