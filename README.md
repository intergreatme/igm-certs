---

# Certificate Generation CLI Application

This interactive command-line application allows you to generate x.509 certificates interactively. It includes functionality to create private keys and self-signed certificates, which can be used for secure communications.

## Features

- **Interactive Menu**: Generate certificates and test existing certificates interactively.
- **Password Protection**: Encrypts private keys with a password for added security.
- **Directory Setup**: Automatically sets up directories to store keys and certificates.

## Prerequisites

- **Go**: Ensure you have Go installed (version 1.20 or later).

## Installation

1. **Clone the Repository**:
    ```sh
    git clone https://github.com/intergreatme/igm-certs
    cd igm-certs
    ```

2. **Install Dependencies**:
    ```sh
    go mod tidy
    ```

3. **Build the Application**:
    ```sh
    go build -o igm-certs main.go
    ```
    OR 
     ```sh
    go run .
    ```

4. **Options**
 - Generate a x.509 Certificate:
    - Prompts you to enter a password to protect the private key.
    - Therafter it prompts you to enter your domain name, organization, country and validity years of certificate  
    - Generates the private key and a self-signed certificate.
    - Saves the encrypted private key and certificate in the keys directory.
 
 - Test Existing Certificates:
    - Tests the existence of cert.pem and key.pem in the keys directory.
    - Verifies the integrity and validity of the existing certificate and key.

 - Quit:
    - Exits the application.

5. **Example run**
```bash
$ go run .
? Select an action: 
  ▸ Generate a x.509 Certificate
    Test Existing Certificates
    Quit

? Enter a password to protect the private key: ********
? Confirm your password: ********
? Common Name (e.g., your domain name): intergreatme.com
? Organization (e.g., company name): Intergreatme
? Country (2-letter code): ZA
? Validity Period (years): 10
Generating certificate, please wait...
Generated successfully, your certificates can be found under /path/to/your/directory/keys
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---