/*
 * Copyright (c) 2024 Intergreatme. All rights reserved.
 */

package test

import (
	"fmt"
	"log"

	"github.com/intergreatme/certcrypto"
	"github.com/intergreatme/igm-certs/file"
)

// TestExistingCertificates checks if the certificate and key files exist and are correctly formatted.
func TestExistingCertificates() error {
	// Set up test directory
	outputPath, err := file.SetupKeysDirectory()
	if err != nil {
		log.Printf("Failed to setup keys directory: %v", err)
		return fmt.Errorf("failed to setup keys directory: %v", err)
	}
	log.Printf("Keys directory set up at %s", outputPath)

	// Verify certificate file exists and is correctly formatted
	certPath := outputPath + "/cert.pem"
	_, err = certcrypto.ReadCertFromPEM(certPath)
	if err != nil {
		log.Printf("Failed to read certificate file: %v", err)
		return fmt.Errorf("failed to read certificate file: %v", err)
	}
	log.Printf("Certificate file exists and is valid: %s", certPath)

	// Verify key file exists and is correctly formatted
	pfxPath := outputPath + "/cert.pfx"
	password := "yourpassword"
	_, _, err = certcrypto.ReadPKCS12(pfxPath, password)
	if err != nil {
		log.Printf("Failed to read key file from PFX: %v", err)
		return fmt.Errorf("failed to read key file from PFX: %v", err)
	}
	log.Printf("Key file exists and is valid: %s", pfxPath)

	return nil
}
