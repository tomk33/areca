package main

import (
	// go imports
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	// package imports
	"github.com/quic-go/quic-go"
	"github.com/tomk33/areca/internal/database"
	"github.com/tomk33/areca/internal/identity"

	// database imports
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// User represents a user account with multiple devices
type User struct {
	ID       string   `json:"_id"`      // MongoDB ID
	Username string   `json:"username"` // User's name/identifier
	Devices  []Device `json:"deviceid"` // List of devices owned by this user
}

// Device represents a device owned by a user
type Device struct {
	ID        string      `json:"deviceid"`   // Unique device identifier
	Name      string      `json:"devicename"` // Human-readable name
	PublicKey interface{} `json:"publickey"`  // Public key data (can be PEM string)
}

func main() {
	// Getting values from user entry (later implemented inside system and a user click on a device name)
	listenAddr := flag.String("listen", ":4433", "")
	peerAddr := flag.String("peer", "", "")
	peerDeviceID := flag.String("peer-id", "", "")

	flag.Parse()

	run(*listenAddr, *peerAddr, *peerDeviceID)
}

func run(listenAddr, peerAddr, peerDeviceID string) error {
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

	// Load and save the current database as a json
	dbLoadSave()

	// Create this devices TLS cert
	cert, err := id.TLSCertificate()
	if err != nil {
		return err
	}

	// Load the selected peer's public key
	peerKey, err := loadPeerPublicKey(peerDeviceID)
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

	// CONITNUE HERE WITH THE MESSAGING SERVICE..........

	return nil
}

func dbLoadSave() error {
	rootDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}

	usersDir := filepath.Join(rootDir, "Areca", "database")

	usersDirPath := filepath.Join(usersDir, "users.json")
	_, usersGetErr := os.Stat(usersDirPath)
	usersExists := usersGetErr == nil

	// Dir made if it doesn't exist
	if !usersExists {
		// Make directory
		err = os.MkdirAll(usersDir, 0700)
		if err != nil {
			return err
		}

		// Make blank json file for later writing of data
		newPath := filepath.Join(usersDir, "users.json")
		if err = os.WriteFile(newPath, []byte{}, 0600); err != nil {
			return err
		}
	}

	// When dir exists set path to users.json
	usersJsonPath := filepath.Join(usersDir, "users.json")

	var uri string

	// ----------------------------
	// ENTER DATABASE URI BELOW ...
	// ----------------------------
	if uri = os.Getenv("MONGODB_URI"); uri == "" {
		log.Fatal("You must set your 'MONGODB_URI' environment variable. See\n\t https://docs.mongodb.com/drivers/go/current/usage-examples/")
	}

	// Uses the SetServerAPIOptions() method to set the Stable API version to 1
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)

	// Defines the options for the MongoDB client
	opts := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPI)

	// Creates a new client and connects to the server
	client, err := mongo.Connect(opts)

	if err != nil {
		panic(err)
	}
	defer func() {
		if err = client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()

	coll := client.Database("arecadb").Collection("users")

	cursor, err := coll.Find(context.Background(), bson.D{})
	if err != nil {
		return err
	}
	defer cursor.Close(context.Background())

	var users []bson.M
	err = cursor.All(context.Background(), &users)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(users)
	if err != nil {
		return err
	}

	if err = os.WriteFile(usersJsonPath, jsonData, 0600); err != nil {
		return err
	}

	return nil
}

func loadAndParseUsers() ([]User, error) {
	rootDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}

	// Define the file path to read from
	usersJsonPath := filepath.Join(rootDir, "Areca", "database", "users.json")

	// Read the JSON file content
	data, err := os.ReadFile(usersJsonPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read json: %w", err)
	}

	var users []User
	err = json.Unmarshal(data, &users)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse json: %w", err)
	}

	return users, nil
}

func loadPeerPublicKey(peerDeviceID string) ([]byte, error) {
	// Loading users.json and parsing into User struct
	users, err := loadAndParseUsers()
	if err != nil {
		return nil, err
	}

	var targetDevice *Device = nil

	for _, user := range users {
		for _, device := range user.Devices {
			if device.ID == peerDeviceID {
				targetDevice = &device
				break // Found the device
			}
		}
	}

	// Return device's public key
	if targetDevice != nil {
		return []byte(targetDevice.PublicKey.(string)), nil
	}

	// Return error if device not found
	return nil, fmt.Errorf("No user or device with ID: %s", peerDeviceID)
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
