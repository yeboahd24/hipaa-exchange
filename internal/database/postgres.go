package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresConfig holds PostgreSQL connection configuration
type PostgresConfig struct {
	Host        string
	Port        int
	Database    string
	User        string
	Password    string
	SSLMode     string
	MaxPoolSize int32
	ConnTimeout time.Duration
}

// Connect establishes a connection to PostgreSQL with HIPAA-compliant settings
func Connect(ctx context.Context, config PostgresConfig) (*pgxpool.Pool, error) {
	// Construct connection string
	connString := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host,
		config.Port,
		config.User,
		config.Password,
		config.Database,
		config.SSLMode,
	)

	// Configure the connection pool
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("error parsing connection string: %v", err)
	}

	// Set pool configuration
	poolConfig.MaxConns = config.MaxPoolSize
	poolConfig.ConnConfig.ConnectTimeout = config.ConnTimeout

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %v", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("unable to ping database: %v", err)
	}

	return pool, nil
}

// Disconnect safely closes the PostgreSQL connection pool
func Disconnect(pool *pgxpool.Pool) error {
	if pool != nil {
		pool.Close()
		return nil
	}
	return nil
}
