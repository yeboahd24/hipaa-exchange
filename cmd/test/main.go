package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	password := "@Linux70"
	storedHash := "$2a$10$tuaPQQHoHXwtW7lT5PpU4uKyGI1hyo/jDZt4C2kXdWkHncfTiC7Nm" // admin's hash

	// Test comparing password with stored hash
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		log.Printf("Password comparison failed: %v", err)
	} else {
		log.Printf("Password comparison succeeded!")
	}

	// Generate a new hash and print it
	newHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	fmt.Printf("New hash for password: %s\n", string(newHash))
}
