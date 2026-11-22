package identity

import (
	"bytes"
	"os"
	"path/filepath"
)

func LoadOrCreate() (*SoftwareIdentity, error) {
	rootDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}

	identityDir := filepath.Join(rootDir, "Areca", "identity")

	err = os.MkdirAll(identityDir, 0700)
	if err != nil {
		return nil, err
	}

	// Restrict directory permissions, including if it already exists
	err = os.Chmod(identityDir, 0700)
	if err != nil {
		return nil, err
	}

	privKeyPath := filepath.Join(identityDir, "private.pem")
	pubKeyPath := filepath.Join(identityDir, "public.pem")

	_, privateErr := os.Stat(privKeyPath)
	_, publicErr := os.Stat(pubKeyPath)

	privExists := privateErr == nil
	pubExists := publicErr == nil

	if privExists != pubExists {
		return nil, os.ErrInvalid
	}

	if privExists && pubExists {
		privatePEM, err := os.ReadFile(privKeyPath)
		if err != nil {
			return nil, err
		}

		publicPEM, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return nil, err
		}

		priv, err := decodePrivateKey(privatePEM)
		if err != nil {
			return nil, err
		}

		pub, err := decodePublicKey(publicPEM)
		if err != nil {
			return nil, err
		}

		// Check that the stored public key matches the private key
		expectedPublic, err := encodePublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}

		actualPublic, err := encodePublicKey(pub)
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(expectedPublic, actualPublic) {
			return nil, os.ErrInvalid
		}

		return &SoftwareIdentity{privateKey: priv}, nil
	}

	// Generate a new identity if neither file exists
	id, err := generateIdentity()
	if err != nil {
		return nil, err
	}

	privatePEM, err := encodePrivateKey(id.privateKey)
	if err != nil {
		return nil, err
	}

	publicPEM, err := encodePublicKey(&id.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	// Create files without overwriting existing ones
	err = saveFile(privKeyPath, privatePEM, 0600)
	if err != nil {
		return nil, err
	}

	err = saveFile(pubKeyPath, publicPEM, 0644)
	if err != nil {
		return nil, err
	}

	return id, nil
}

func saveFile(path string, data []byte, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		file.Close()
		os.Remove(path)
		return err
	}

	// LATER ADD INTEGRITY TO ENSURE NO PARTIAL KEYS

	return file.Close()
}
