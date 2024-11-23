package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/joho/godotenv"
	"github.com/mesikahq/hipaa-exchange/internal/audit"
	"github.com/mesikahq/hipaa-exchange/internal/auth"
	"github.com/mesikahq/hipaa-exchange/internal/database"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Parse command line flags
	username := flag.String("username", "", "Admin username")
	password := flag.String("password", "", "Admin password")
	email := flag.String("email", "", "Admin email")
	flag.Parse()

	if *username == "" || *password == "" || *email == "" {
		log.Fatal("Username, password, and email are required. Use -username, -password, and -email flags")
	}

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading .env file: %v", err)
	}

	// Initialize Elasticsearch client for audit logging
	cfg := elasticsearch.Config{
		Addresses: []string{os.Getenv("ELASTICSEARCH_URL")},
		Username:  os.Getenv("ELASTICSEARCH_USERNAME"),
		Password:  os.Getenv("ELASTICSEARCH_PASSWORD"),
	}
	esClient, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to Elasticsearch: %v", err)
	}

	// Initialize audit service
	auditService := audit.NewService(esClient)

	// Initialize PostgreSQL connection
	postgresConfig := database.PostgresConfig{
		Host:        os.Getenv("POSTGRES_HOST"),
		Port:        5432, // Default PostgreSQL port
		Database:    os.Getenv("POSTGRES_DB"),
		User:        os.Getenv("POSTGRES_USER"),
		Password:    os.Getenv("POSTGRES_PASSWORD"),
		SSLMode:     os.Getenv("POSTGRES_SSLMODE"),
		MaxPoolSize: 1,
		ConnTimeout: 5 * time.Second,
	}

	ctx := context.Background()
	db, err := database.Connect(ctx, postgresConfig)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer database.Disconnect(db)

	// Initialize auth service
	authConfig := auth.AuthServiceConfig{
		JWTSecret:    os.Getenv("JWT_SECRET"),
		TokenExpiry:  24 * time.Hour,
		RefreshLimit: 7 * 24 * time.Hour,
	}
	authService := auth.NewService(db, auditService, authConfig)

	// Initialize database schema
	if err := authService.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	// Create admin user
	user, err := authService.Register(ctx, *username, *email, *password, []string{"admin"})
	if err != nil {
		log.Fatalf("Failed to create admin user: %v", err)
	}

	fmt.Printf("Successfully created admin user:\n")
	fmt.Printf("ID: %s\n", user.ID)
	fmt.Printf("Username: %s\n", user.Username)
	fmt.Printf("Roles: %v\n", user.Roles)

	// Verify the password hash
	var hashedPassword string
	err = db.QueryRow(ctx, "SELECT password_hash FROM users WHERE username = $1", *username).Scan(&hashedPassword)
	if err != nil {
		log.Fatalf("Failed to get user password hash: %v", err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(*password))
	if err != nil {
		log.Printf("WARNING: Password verification failed: %v", err)
	} else {
		log.Printf("Password hash verified successfully")
	}
}
