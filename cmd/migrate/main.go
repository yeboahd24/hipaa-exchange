package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
	"github.com/mesikahq/hipaa-exchange/internal/db"
	"github.com/mesikahq/hipaa-exchange/internal/db/migrate"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}

	// Parse command line flags
	command := flag.String("command", "up", "Migration command (up/down)")
	migrationsDir := flag.String("dir", "internal/db/migrations", "Migrations directory")
	flag.Parse()

	// Get database configuration from environment
	dbConfig := db.Config{
		Host:     getEnv("POSTGRES_HOST", "localhost"),
		Port:     getEnvAsInt("POSTGRES_PORT", 5432),
		User:     getEnv("POSTGRES_USER", "postgres"),
		Password: getEnv("POSTGRES_PASSWORD", ""),
		Database: getEnv("POSTGRES_DB", "hipaa_exchange"),
		SSLMode:  getEnv("DB_SSLMODE", "disable"),
	}

	// Create database connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.NewConnection(dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	// Create migration manager
	absPath, err := filepath.Abs(*migrationsDir)
	if err != nil {
		log.Fatalf("Failed to get absolute path: %v", err)
	}

	manager := migrate.NewManager(pool, absPath)

	// Initialize migrations table
	if err := manager.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize migrations: %v", err)
	}

	// Run migration command
	switch *command {
	case "up":
		if err := manager.Up(ctx); err != nil {
			log.Fatalf("Failed to apply migrations: %v", err)
		}
		fmt.Println("Successfully applied all pending migrations")

	case "down":
		if err := manager.Down(ctx); err != nil {
			log.Fatalf("Failed to roll back migration: %v", err)
		}
		fmt.Println("Successfully rolled back last migration")

	default:
		log.Fatalf("Unknown command: %s", *command)
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		var result int
		if _, err := fmt.Sscanf(value, "%d", &result); err == nil {
			return result
		}
	}
	return fallback
}
