package main

import (
	"flag"
	"fmt"

	"github.com/intergreatme/igm-certs/certificate"
	"github.com/intergreatme/igm-certs/test"
	"github.com/manifoldco/promptui"
)

func main() {
	// Define a flag for the RSA key size
	bitsFlag := flag.Int("bits", 4096, "Size of the RSA key in bits")
	flag.Parse()

	// Display a selection prompt to the user for generating a certificate or quitting
	prompt := promptui.Select{
		Label: "Select an action",
		Items: []string{"Generate a x509 Certificate", "Test existing Certificates", "Quit"},
	}

	// Run the prompt and handle the user's selection
	_, result, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	switch result {
	case "Generate a x509 Certificate":
		// Handle the x509 certificate generation process
		err := certificate.HandleX509Generation(*bitsFlag)
		if err != nil {
			fmt.Printf("Operation failed: %v\n", err)
		}
	case "Test existing Certificates":
		// Run the certificate test function
		err := test.TestExistingCertificates()
		if err != nil {
			fmt.Printf("Certificate test failed: %v\n", err)
		} else {
			fmt.Println("Certificate test passed successfully.")
		}

	case "Quit":
		// Professional exit message
		fmt.Println("Exiting application.")
		return
	}
}
