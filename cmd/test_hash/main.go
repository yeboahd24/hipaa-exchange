package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	// The stored password hash from the database for admin user
	storedHash := "$2a$10$tuaPQQHoHXwtW7lT5PpU4uKyGI1hyo/jDZt4C2kXdWkHncfTiC7Nm"
	password := "@Linux70"

	// Test password comparison
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		log.Printf("Password comparison failed: %v", err)
	} else {
		log.Printf("Password comparison succeeded!")
	}

	// Generate a new hash and compare
	newHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	fmt.Printf("New hash: %s\n", string(newHash))

	// Compare with new hash
	err = bcrypt.CompareHashAndPassword(newHash, []byte(password))
	if err != nil {
		log.Printf("New hash comparison failed: %v", err)
	} else {
		log.Printf("New hash comparison succeeded!")
	}
}
