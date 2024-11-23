package migrate

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration represents a single database migration
type Migration struct {
	Version   int
	Name      string
	UpSQL     string
	DownSQL   string
	AppliedAt *time.Time
}

// Manager handles database migrations
type Manager struct {
	db       *pgxpool.Pool
	migrationsDir string
}

// NewManager creates a new migration manager
func NewManager(db *pgxpool.Pool, migrationsDir string) *Manager {
	return &Manager{
		db:       db,
		migrationsDir: migrationsDir,
	}
}

// Initialize creates the migrations table if it doesn't exist
func (m *Manager) Initialize(ctx context.Context) error {
	sql := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`
	_, err := m.db.Exec(ctx, sql)
	return err
}

// LoadMigrations reads migration files from the migrations directory
func (m *Manager) LoadMigrations() ([]Migration, error) {
	files, err := ioutil.ReadDir(m.migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	migrations := make(map[int]Migration)
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		// Parse version and type from filename (e.g., 001_initial_schema.sql or 001_initial_schema_down.sql)
		parts := strings.Split(strings.TrimSuffix(name, ".sql"), "_")
		if len(parts) < 2 {
			continue
		}

		version := 0
		fmt.Sscanf(parts[0], "%d", &version)
		if version == 0 {
			continue
		}

		content, err := ioutil.ReadFile(filepath.Join(m.migrationsDir, name))
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", name, err)
		}

		migration, exists := migrations[version]
		if !exists {
			migration = Migration{
				Version: version,
				Name:    strings.Join(parts[1:], "_"),
			}
		}

		if strings.HasSuffix(name, "_down.sql") {
			migration.DownSQL = string(content)
		} else {
			migration.UpSQL = string(content)
		}

		migrations[version] = migration
	}

	// Convert map to slice and sort
	result := make([]Migration, 0, len(migrations))
	for _, m := range migrations {
		result = append(result, m)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Version < result[j].Version
	})

	return result, nil
}

// GetAppliedMigrations returns all applied migrations
func (m *Manager) GetAppliedMigrations(ctx context.Context) (map[int]time.Time, error) {
	rows, err := m.db.Query(ctx, "SELECT version, applied_at FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]time.Time)
	for rows.Next() {
		var version int
		var appliedAt time.Time
		if err := rows.Scan(&version, &appliedAt); err != nil {
			return nil, fmt.Errorf("failed to scan migration row: %w", err)
		}
		applied[version] = appliedAt
	}

	return applied, nil
}

// Up applies all pending migrations
func (m *Manager) Up(ctx context.Context) error {
	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}

	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		if _, ok := applied[migration.Version]; ok {
			continue // Skip already applied migrations
		}

		// Begin transaction
		tx, err := m.db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		// Apply migration
		if _, err := tx.Exec(ctx, migration.UpSQL); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}

		// Record migration
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
			migration.Version, migration.Name); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("failed to record migration %d: %w", migration.Version, err)
		}

		// Commit transaction
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit migration %d: %w", migration.Version, err)
		}

		fmt.Printf("Applied migration %d: %s\n", migration.Version, migration.Name)
	}

	return nil
}

// Down rolls back the last migration
func (m *Manager) Down(ctx context.Context) error {
	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}

	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	if len(applied) == 0 {
		return fmt.Errorf("no migrations to roll back")
	}

	// Find the last applied migration
	var lastVersion int
	for version := range applied {
		if version > lastVersion {
			lastVersion = version
		}
	}

	// Find the migration with this version
	var migration Migration
	for _, m := range migrations {
		if m.Version == lastVersion {
			migration = m
			break
		}
	}

	// Begin transaction
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Apply down migration
	if _, err := tx.Exec(ctx, migration.DownSQL); err != nil {
		tx.Rollback(ctx)
		return fmt.Errorf("failed to roll back migration %d: %w", migration.Version, err)
	}

	// Remove migration record
	if _, err := tx.Exec(ctx,
		"DELETE FROM schema_migrations WHERE version = $1",
		migration.Version); err != nil {
		tx.Rollback(ctx)
		return fmt.Errorf("failed to remove migration record %d: %w", migration.Version, err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit rollback of migration %d: %w", migration.Version, err)
	}

	fmt.Printf("Rolled back migration %d: %s\n", migration.Version, migration.Name)
	return nil
}
