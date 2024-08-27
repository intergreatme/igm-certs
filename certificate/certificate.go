/*
 * Copyright (c) 2024 Intergreatme. All rights reserved.
 */

package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/intergreatme/igm-certs/file"
	"github.com/manifoldco/promptui"
	"software.sslmate.com/src/go-pkcs12"
)

// CertificateDetails contains the details for the certificate.
type CertificateDetails struct {
	CommonName    string
	Organization  string
	Country       string
	ValidityYears int // New field for the certificate validity period in years
}

// HandleX509Generation handles the entire process of generating an x509 certificate.
func HandleX509Generation(bits int) error {
	// Set up the directory to store the keys
	keysPath, err := file.SetupKeysDirectory()
	if err != nil {
		return fmt.Errorf("failed to setup keys directory: %v", err)
	}

	// Handle the password prompt and confirmation
	password, err := HandlePassword()
	if err != nil {
		return fmt.Errorf("password handling failed: %v", err)
	}

	// Define certificate details
	details := CertificateDetails{}

	// Prompts
	prompts := []struct {
		label    string
		value    *string
		validate promptui.ValidateFunc
	}{
		{"Common Name (e.g., your domain name)", &details.CommonName, nil},
		{"Organization (e.g., company name)", &details.Organization, nil},
		{"Country (2-letter code)", &details.Country, validateCountryCode},
		{"Validity Period (years)", nil, validateYears},
	}

	for _, p := range prompts {
		prompt := promptui.Prompt{
			Label:    p.label,
			Validate: p.validate,
		}
		result, err := prompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return err
		}
		if p.value != nil {
			*p.value = result
		} else {
			// Handle validity period separately
			validityYears, err := strconv.Atoi(result)
			if err != nil {
				fmt.Printf("Invalid number: %v\n", err)
				return err
			}
			details.ValidityYears = validityYears
		}
	}

	// Generate the x509 certificate and store it in the keys directory
	fmt.Println("Generating certificate, please wait...")
	err = GenerateCertificate(keysPath, password, details, bits)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	// Notify the user of successful certificate generation
	fmt.Printf("Generated successfully, your certificates can be found under %s\n", keysPath)
	fmt.Printf("Exiting application.\n")

	return nil
}

// validateYears ensures the input is a valid number of years.
func validateYears(input string) error {
	_, err := strconv.Atoi(input)
	if err != nil {
		return fmt.Errorf("invalid number of years")
	}
	return nil
}

// validateCountryCode ensures the input is a valid 2-letter country code.
func validateCountryCode(input string) error {
	if match, _ := regexp.MatchString(`^[A-Za-z]{2}$`, input); !match {
		return fmt.Errorf("invalid country code")
	}
	return nil
}

// GenerateCertificate generates an x509 certificate and stores it in the specified output path.
func GenerateCertificate(outputPath, password string, details CertificateDetails, bits int) error {
	if bits == 4096 {
		fmt.Println("Using default RSA key size of 4096 bits. To change this, run the app with --bits=<size>")
	} else {
		fmt.Printf("Using custom RSA key size of %d bits.\n", bits)
	}

	// Generate a new RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	// Define certificate validity period in days
	notBefore := time.Now()
	notAfter := notBefore.AddDate(details.ValidityYears, 0, 0)

	// Generate a random serial number for the certificate
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return err
	}

	// Create a certificate template with the provided details
	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		Subject: pkix.Name{
			CommonName:   details.CommonName,
			Organization: []string{details.Organization},
			Country:      []string{details.Country},
		},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA512WithRSA,
	}

	// Create the selfsigned certificate | This is an essential step because it transforms the certificate template into an actual valid certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Parse the DER-encoded bytes to get an x509.Certificate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return err
	}

	// Write the certificate to a PEM file
	certPath := filepath.Join(outputPath, "cert.pem")
	if err := file.WriteCertToPEM(cert, certPath); err != nil {
		return err
	}

	// Export cert to PFX
	pfxPath := filepath.Join(outputPath, "cert.pfx")
	if err := ExportCertToPFX(pfxPath, priv, cert, password); err != nil {
		return err
	}

	return nil
}

// ExportCertToPFX exports the certificate and private key to a PFX file.
func ExportCertToPFX(pfxPath string, priv *rsa.PrivateKey, cert *x509.Certificate, password string) error {
	// Encode the certificate and private key into a PFX file
	pfxData, err := pkcs12.Modern2023.Encode(priv, cert, nil, password)
	if err != nil {
		return fmt.Errorf("failed to encode PFX: %v", err)
	}

	// Write the PFX data to a file
	err = os.WriteFile(pfxPath, pfxData, 0644)
	if err != nil {
		return fmt.Errorf("unable to write PFX to file: %v", err)
	}

	return nil
}
