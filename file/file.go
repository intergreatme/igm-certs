package file

import (
	"crypto/x509"
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

// WriteCertToPEM writes an x509 certificate to a PEM-encoded file.
func WriteCertToPEM(cert *x509.Certificate, filepath string) error {
	// Encode the certificate into a PEM block
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Write the PEM block to the specified file
	err := os.WriteFile(filepath, certPEM, 0644)
	if err != nil {
		return fmt.Errorf("unable to write certificate to file: %v", err)
	}

	return nil
}
