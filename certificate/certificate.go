package certificate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"time"

	"intergreatme.com/igm-certs/file"
)

// HandleX509Generation handles the entire process of generating an x509 certificate.
func HandleX509Generation() error {
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

	// Generate the x509 certificate and store it in the keys directory
	fmt.Println("Generating certificate, please wait...")
	err = GenerateCertificate(keysPath, password)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	// Notify the user of successful certificate generation
	fmt.Printf("Generated successfully, your certificates can be found under %s\n", keysPath)

	fmt.Printf("Exiting application.\n")

	return nil
}

// GenerateCertificate generates an x509 certificate and stores it in the specified output path.
func GenerateCertificate(outputPath, password string) error {
	// Generate a new RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Define certificate validity period
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	// Generate a random serial number for the certificate
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return err
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Define file paths for the certificate and the private key
	certPath := filepath.Join(outputPath, "cert.pem")
	keyPath := filepath.Join(outputPath, "key.pem")

	// Write the certificate to a PEM file
	if err := file.WritePemFile(certPath, "CERTIFICATE", derBytes); err != nil {
		return err
	}

	// Marshal the private key to PKCS1 format
	privBytes := x509.MarshalPKCS1PrivateKey(priv)

	// Encrypt the private key
	encPrivKey, err := encryptPrivateKey(privBytes, password)
	if err != nil {
		return err
	}

	// Write the encrypted private key to a PEM file
	if err := file.WritePemFile(keyPath, "ENCRYPTED PRIVATE KEY", encPrivKey); err != nil {
		return err
	}

	return nil
}

// encryptPrivateKey encrypts the private key using AES-GCM with the provided password.
func encryptPrivateKey(privateKey []byte, password string) ([]byte, error) {
	// Derive a key from the password using SHA-256.
	// The derived key is 32 bytes long, suitable for AES-256 encryption.
	hash := sha256.Sum256([]byte(password))

	// Create a new AES cipher block from the derived key.
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}

	// Create a new GCM (Galois/Counter Mode) AEAD (Authenticated Encryption with Associated Data) cipher.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce for GCM. The nonce size is specific to the GCM instance.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the private key using AES-GCM. The nonce is used as the initialization vector.
	// The resulting ciphertext includes the nonce followed by the encrypted private key.
	ciphertext := gcm.Seal(nonce, nonce, privateKey, nil)

	// Return the resulting ciphertext.
	return ciphertext, nil
}
