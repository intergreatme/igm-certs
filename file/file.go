package file

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// SetupKeysDirectory sets up the directory to store the keys.
func SetupKeysDirectory() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}

	keysPath := filepath.Join(currentDir, "keys")

	// Check if keys path exists and create it if it doesn't exist
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		err := os.MkdirAll(keysPath, 0755)
		if err != nil {
			return "", fmt.Errorf("failed to create directory: %w", err)
		}
	}

	return keysPath, nil
}

// WritePemFile writes the provided bytes to a PEM file with the specified type.
func WritePemFile(path, pemType string, bytes []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	block := &pem.Block{
		Type:  pemType,
		Bytes: bytes,
	}

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("failed to write PEM file: %w", err)
	}

	return nil
}
