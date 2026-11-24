package database

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/tomk33/areca/internal/identity"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type DeviceRegister struct {
	DeviceID   string `json:"deviceId"`
	Username   string `json:"username"`
	DeviceName string `json:"deviceName"`
	PublicKey  string `json:"publicKey"`
}

func RegisterDevice(id identity.Identity, device *LocalDevice) error {
	// Asking user for details of device
	rdr := bufio.NewReader(os.Stdin)

	fmt.Print("Enter your username: ")
	username, _ := rdr.ReadString('\n')

	fmt.Print("Enter device name: ")
	deviceName, _ := rdr.ReadString('\n')

	if username == "" || deviceName == "" {
		return fmt.Errorf("username and device name cannot be empty")
	}

	// Neatening of inputs
	username = strings.TrimSpace(username)
	deviceName = strings.TrimSpace(deviceName)

	publicKey, err := id.PublicKey()
	if err != nil {
		return err
	}

	registrationDoc := DeviceRegister{
		DeviceID:   device.DeviceID,
		Username:   username,
		DeviceName: deviceName,
		PublicKey:  string(publicKey),
	}

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

	result, err := coll.InsertOne(context.TODO(), registrationDoc)

	fmt.Printf("Inserted document with _id: %v\n", result.InsertedID)

	// Update current device's username and device name with inputted
	device.Username = username
	device.DeviceName = deviceName

	localData, err := json.Marshal(device)
	if err != nil {
		return err
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}

	devicePath := filepath.Join(configDir, "Areca", "db", "device.json")

	err = os.WriteFile(devicePath, localData, 0600)
	if err != nil {
		return err
	}

	fmt.Println("This device is now registered")

	return nil
}
