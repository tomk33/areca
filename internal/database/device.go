package database

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

type LocalDevice struct {
	DeviceID   string `json:"deviceId"`
	Username   string `json:"username"`
	DeviceName string `json:"deviceName"`
}

func LoadOrCreateDevice() (*LocalDevice, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}

	// Making db folder in app data folder
	dbDir := filepath.Join(cfgDir, "Areca", "db")
	err = os.MkdirAll(dbDir, 0700)
	if err != nil {
		return nil, err
	}

	// Reading device.json or creating if doesn't exist
	devicePath := filepath.Join(dbDir, "device.json")
	data, err := os.ReadFile(devicePath)
	if err == nil {
		var device LocalDevice

		// Parse the data to the device structure
		err = json.Unmarshal(data, &device)
		if err != nil {
			return nil, err
		}

		return &device, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	// Generating and setting new UUID
	newUUID, err := exec.Command("uuidgen").Output()
	if err != nil {
		log.Fatal(err)
	}
	device := &LocalDevice{
		DeviceID: string(newUUID),
	}

	data, err = json.Marshal(device)
	if err != nil {
		return nil, err
	}

	// Writing data to the device.json file
	err = os.WriteFile(devicePath, data, 0600)
	if err != nil {
		return nil, err
	}

	return device, nil
}
