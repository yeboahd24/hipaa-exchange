package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/mesikahq/hipaa-exchange/internal/api"
	"github.com/mesikahq/hipaa-exchange/internal/audit"
	"github.com/mesikahq/hipaa-exchange/internal/auth"
	"github.com/mesikahq/hipaa-exchange/internal/config"
	"github.com/mesikahq/hipaa-exchange/internal/consent"
	"github.com/mesikahq/hipaa-exchange/internal/careplan"
	"github.com/mesikahq/hipaa-exchange/internal/database"
	"github.com/mesikahq/hipaa-exchange/internal/encryption"
	"github.com/mesikahq/hipaa-exchange/internal/patient"
	"github.com/mesikahq/hipaa-exchange/internal/provider"
	"go.uber.org/zap"

	"github.com/elastic/go-elasticsearch/v8"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading .env file: %v", err)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Initialize PostgreSQL connection
	pgPort, err := strconv.Atoi(os.Getenv("POSTGRES_PORT"))
	if err != nil {
		logger.Fatal("Failed to get PostgreSQL port", zap.Error(err))
	}

	postgresConfig := database.PostgresConfig{
		Host:        os.Getenv("POSTGRES_HOST"),
		Port:        pgPort,
		Database:    os.Getenv("POSTGRES_DB"),
		User:        os.Getenv("POSTGRES_USER"),
		Password:    os.Getenv("POSTGRES_PASSWORD"),
		SSLMode:     os.Getenv("POSTGRES_SSLMODE"),
		MaxPoolSize: 10,
		ConnTimeout: 5 * time.Second,
	}

	ctx := context.Background()
	db, err := database.Connect(ctx, postgresConfig)
	if err != nil {
		logger.Fatal("Failed to connect to PostgreSQL", zap.Error(err))
	}
	defer database.Disconnect(db)

	// Initialize encryption service
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		logger.Fatal("ENCRYPTION_KEY environment variable is required")
	}
	encryptService, err := encryption.NewService()
	if err != nil {
		logger.Fatal("Failed to initialize encryption service", zap.Error(err))
	}

	// Initialize Elasticsearch client
	cfgElastic := elasticsearch.Config{
		Addresses: []string{os.Getenv("ELASTICSEARCH_URL")},
		Username:  os.Getenv("ELASTICSEARCH_USERNAME"),
		Password:  os.Getenv("ELASTICSEARCH_PASSWORD"),
	}
	esClient, err := elasticsearch.NewClient(cfgElastic)
	if err != nil {
		logger.Fatal("Failed to connect to Elasticsearch", zap.Error(err))
	}

	// Initialize audit service
	auditService := audit.NewService(esClient)

	// Initialize auth service
	authConfig := auth.AuthServiceConfig{
		JWTSecret:    os.Getenv("JWT_SECRET"),
		TokenExpiry:  24 * time.Hour,
		RefreshLimit: 7 * 24 * time.Hour,
	}

	authService := auth.NewService(db, auditService, authConfig)
	if err := authService.Initialize(context.Background()); err != nil {
		logger.Fatal("Failed to initialize auth service", zap.Error(err))
	}

	// Initialize services
	providerService := provider.NewService(db, encryptService, auditService)
	patientService := patient.NewService(db, encryptService, auditService, providerService)
	consentService := consent.NewService(db, auditService)
	carePlanService := careplan.NewService(db, auditService)

	// Initialize handler
	handler := api.NewHandler(
		authService,
		patientService,
		providerService,
		consentService,
		carePlanService,
		auditService,
	)

	// Initialize router
	router := api.NewRouter(handler, &authService)
	engine := router.SetupRouter(logger)

	// Create server
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: engine,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on %s:%d", cfg.Server.Host, cfg.Server.Port)
		if cfg.Server.TLS.Enabled {
			if err := srv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start server: %v", err)
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}
