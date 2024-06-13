# Certificate Generation CLI Application

This interactive command-line application allows you to generate x.509 certificates interactively. It includes functionality to create private keys and self-signed certificates, which can be used for secure communications.

## Features

- **Interactive Menu**: Generate certificates and test existing certificates interactively.
- **Password Protection**: Encrypts private keys with a password for added security.
- **Directory Setup**: Automatically sets up directories to store keys and certificates.
- **Customizable Key Size**: Option to specify the size of the RSA key (default is 4096 bits).

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

4. **Run the Application**:
    ```sh
    ./igm-certs
    ```
    OR 
     ```sh
    go run .
    ```

## Usage

### Generate a x.509 Certificate

- Prompts you to enter a password to protect the private key.
- Thereafter it prompts you to enter your domain name, organization, country, and validity years of the certificate.
- Generates the private key and a self-signed certificate.
- Saves the encrypted private key and certificate in the keys directory.
- By default, generates a 4096-bit RSA key. To specify a different key size, run the application with the --bits flag:
    ```sh
    go run . --bits=2048
    ```
    This will generate a 2048-bit RSA key instead of the default 4096-bit key.

### Test Existing Certificates

- Tests the existence of `cert.pem` and `cert.pfx` in the keys directory.
- Verifies the integrity and validity of the existing certificate and key.
- Note: You will need to manually input the password for `cert.pfx`.

### Quit

- Exits the application.


5. **Example run**
## Example Run

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