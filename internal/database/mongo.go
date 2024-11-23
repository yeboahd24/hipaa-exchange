package database

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Config represents the configuration for MongoDB connection
type Config struct {
	URI                    string
	Database              string
	MaxPoolSize           uint64
	MinPoolSize           uint64
	MaxConnecting         uint64
	ConnectTimeout        time.Duration
	HeartbeatInterval     time.Duration
	ServerSelectionTimeout time.Duration
	TLSEnabled            bool
	TLSCAFile             string
	TLSCertFile           string
	TLSKeyFile            string
}

// NewMongoClient creates a new MongoDB client with the given configuration
func NewMongoClient(ctx context.Context, cfg *Config) (*mongo.Client, error) {
	// Create MongoDB client options
	clientOptions := options.Client().
		ApplyURI(cfg.URI).
		SetMaxPoolSize(cfg.MaxPoolSize).
		SetMinPoolSize(cfg.MinPoolSize).
		SetMaxConnecting(cfg.MaxConnecting).
		SetConnectTimeout(cfg.ConnectTimeout).
		SetHeartbeatInterval(cfg.HeartbeatInterval).
		SetServerSelectionTimeout(cfg.ServerSelectionTimeout)

	// Configure TLS if enabled
	if cfg.TLSEnabled {
		tlsConfig, err := createTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %v", err)
		}
		clientOptions.SetTLSConfig(tlsConfig)
	}

	// Connect to MongoDB
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	// Verify the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	return client, nil
}

// createTLSConfig creates a TLS configuration for MongoDB connection
func createTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	// Load CA certificate
	if cfg.TLSCAFile != "" {
		caCert, err := ioutil.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %v", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate and key
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}
