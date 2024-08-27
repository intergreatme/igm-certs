/*
 * Copyright (c) 2024 Intergreatme. All rights reserved.
 */

package certificate

import (
	"errors"
	"fmt"

	"github.com/manifoldco/promptui"
)

// PromptPassword prompts the user to enter a password with masking and validation.
func PromptPassword(label string) (string, error) {
	validate := func(input string) error {
		if len(input) < 6 {
			return errors.New("password must be at least 6 characters")
		}
		return nil
	}

	passwordPrompt := promptui.Prompt{
		Label:    label,
		Mask:     '*',
		Validate: validate,
	}

	return passwordPrompt.Run()
}

// HandlePassword handles prompting the user to enter and confirm a password.
func HandlePassword() (string, error) {
	password, err := PromptPassword("Enter a password to protect the private key")
	if err != nil {
		return "", fmt.Errorf("prompt failed: %v", err)
	}

	confirmPassword, err := PromptPassword("Confirm your password")
	if err != nil {
		return "", fmt.Errorf("prompt failed: %v", err)
	}

	if password != confirmPassword {
		return "", errors.New("passwords do not match")
	}

	return password, nil
}
