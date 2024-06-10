package test

import (
	"fmt"
	"log"
	"os"

	"github.com/intergreatme/igm-certs/file"
)

// TestExistingCertificates tests the existing certificates in the keys directory.
func TestExistingCertificates() error {
	// Set up test directory
	outputPath, err := file.SetupKeysDirectory()
	if err != nil {
		log.Printf("Failed to setup keys directory: %v", err)
		return fmt.Errorf("failed to setup keys directory: %v", err)
	}
	log.Printf("Keys directory set up at %s", outputPath)

	// Verify certificate file exists
	certPath := outputPath + "/cert.pem"
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		log.Printf("Certificate file does not exist: %s", certPath)
		return fmt.Errorf("certificate file does not exist: %s", certPath)
	}
	log.Printf("Certificate file exists: %s", certPath)

	// Verify key file exists
	keyPath := outputPath + "/key.pem"
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Printf("Key file does not exist: %s", keyPath)
		return fmt.Errorf("key file does not exist: %s", keyPath)
	}
	log.Printf("Key file exists: %s", keyPath)

	return nil
}
