package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mesikahq/hipaa-exchange/internal/audit"
	"github.com/mesikahq/hipaa-exchange/internal/encryption"
)

var (
	ErrProviderNotFound      = errors.New("provider not found")
	ErrInvalidProviderData   = errors.New("invalid provider data")
	ErrMissingNPI            = errors.New("missing NPI number")
	ErrMissingCertifications = errors.New("missing required certifications")
	ErrExpiredCertification  = errors.New("one or more certifications have expired")
	ErrUnauthorizedAccess    = errors.New("unauthorized access to provider data")
)

type Service interface {
	Register(ctx context.Context, provider *Provider) error
	Get(ctx context.Context, id string) (*Provider, error)
	Update(ctx context.Context, provider *Provider) error
	Deactivate(ctx context.Context, id string) error
	Search(ctx context.Context, query map[string]interface{}) ([]*Provider, error)
	VerifyCertifications(ctx context.Context, id string) error
	GenerateAPIKey(ctx context.Context, id string) (string, error)
	ValidateAPIKey(ctx context.Context, apiKey string) (*Provider, error)
}

type service struct {
	db         *pgxpool.Pool
	encrypt    encryption.Service
	audit      audit.Service
}

func NewService(db *pgxpool.Pool, encrypt encryption.Service, audit audit.Service) Service {
	return &service{
		db:         db,
		encrypt:    encrypt,
		audit:      audit,
	}
}

func (s *service) Register(ctx context.Context, provider *Provider) error {
	if err := provider.Validate(); err != nil {
		return err
	}

	// Encrypt sensitive fields
	if err := s.encryptProviderData(provider); err != nil {
		return err
	}

	// Generate API key
	apiKey, err := s.generateNewAPIKey()
	if err != nil {
		return err
	}

	encryptedAPIKey, err := s.encrypt.Encrypt([]byte(apiKey))
	if err != nil {
		return err
	}
	provider.APIKey = encryptedAPIKey

	// Set metadata
	now := time.Now()
	provider.CreatedAt = now
	provider.UpdatedAt = now
	provider.LastVerified = now

	userID := ctx.Value("user_id").(string)
	provider.VerifiedBy = userID

	// Insert into database
	_, err = s.db.Exec(ctx, `
		INSERT INTO providers (
			id,
			type,
			npi,
			tax_id,
			api_key,
			created_at,
			updated_at,
			last_verified,
			verified_by
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9
		)
	`, provider.ID, provider.Type, provider.NPI, provider.TaxID, provider.APIKey, provider.CreatedAt, provider.UpdatedAt, provider.LastVerified, provider.VerifiedBy)
	if err != nil {
		return err
	}

	// Log audit event
	details, err := json.Marshal(map[string]interface{}{
		"provider_type": provider.Type,
		"npi":           provider.NPI,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal audit event details: %v", err)
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "REGISTER",
		Resource:    "provider",
		ResourceID:  provider.ID,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	return nil
}

func (s *service) Get(ctx context.Context, id string) (*Provider, error) {
	var provider Provider
	err := s.db.QueryRow(ctx, `
		SELECT
			id,
			type,
			npi,
			tax_id,
			api_key,
			created_at,
			updated_at,
			last_verified,
			verified_by
		FROM providers
		WHERE id = $1
	`, id).Scan(
		&provider.ID,
		&provider.Type,
		&provider.NPI,
		&provider.TaxID,
		&provider.APIKey,
		&provider.CreatedAt,
		&provider.UpdatedAt,
		&provider.LastVerified,
		&provider.VerifiedBy,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, ErrProviderNotFound
		}
		return nil, err
	}

	// Decrypt sensitive fields
	if err := s.decryptProviderData(&provider); err != nil {
		return nil, err
	}

	// Log audit event
	details, err := json.Marshal(map[string]interface{}{
		"provider_type": provider.Type,
		"npi":           provider.NPI,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit event details: %v", err)
	}

	userID := ctx.Value("user_id").(string)
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      userID,
		Action:      "READ",
		Resource:    "provider",
		ResourceID:  id,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	return &provider, nil
}

func (s *service) Update(ctx context.Context, provider *Provider) error {
	if err := provider.Validate(); err != nil {
		return err
	}

	// Encrypt sensitive fields
	if err := s.encryptProviderData(provider); err != nil {
		return err
	}

	// Update metadata
	provider.UpdatedAt = time.Now()
	userID := ctx.Value("user_id").(string)

	// Update in database
	_, err := s.db.Exec(ctx, `
		UPDATE providers
		SET
			type = $1,
			npi = $2,
			tax_id = $3,
			api_key = $4,
			updated_at = $5,
			verified_by = $6
		WHERE id = $7
	`, provider.Type, provider.NPI, provider.TaxID, provider.APIKey, provider.UpdatedAt, userID, provider.ID)
	if err != nil {
		return err
	}

	// Log audit event
	details, err := json.Marshal(map[string]interface{}{
		"provider_type": provider.Type,
		"npi":           provider.NPI,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal audit event details: %v", err)
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "UPDATE",
		Resource:    "provider",
		ResourceID:  provider.ID,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	return nil
}

func (s *service) Deactivate(ctx context.Context, id string) error {
	userID := ctx.Value("user_id").(string)
	now := time.Now()

	_, err := s.db.Exec(ctx, `
		UPDATE providers
		SET
			status = 'INACTIVE',
			updated_at = $1
		WHERE id = $2
	`, now, id)
	if err != nil {
		return err
	}

	// Log audit event
	details, err := json.Marshal(map[string]interface{}{
		"provider_type": "",
		"npi":           "",
	})
	if err != nil {
		return fmt.Errorf("failed to marshal audit event details: %v", err)
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "DEACTIVATE",
		Resource:    "provider",
		ResourceID:  id,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	return nil
}

func (s *service) Search(ctx context.Context, query map[string]interface{}) ([]*Provider, error) {
	rows, err := s.db.Query(ctx, `
		SELECT
			id,
			type,
			npi,
			tax_id,
			api_key,
			created_at,
			updated_at,
			last_verified,
			verified_by
		FROM providers
		WHERE status = 'ACTIVE'
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []*Provider
	for rows.Next() {
		var provider Provider
		if err := rows.Scan(
			&provider.ID,
			&provider.Type,
			&provider.NPI,
			&provider.TaxID,
			&provider.APIKey,
			&provider.CreatedAt,
			&provider.UpdatedAt,
			&provider.LastVerified,
			&provider.VerifiedBy,
		); err != nil {
			return nil, err
		}
		if err := s.decryptProviderData(&provider); err != nil {
			return nil, err
		}
		providers = append(providers, &provider)
	}

	return providers, nil
}

func (s *service) VerifyCertifications(ctx context.Context, id string) error {
	provider, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	if err := provider.validateCertifications(); err != nil {
		return err
	}

	userID := ctx.Value("user_id").(string)
	now := time.Now()

	_, err = s.db.Exec(ctx, `
		UPDATE providers
		SET
			last_verified = $1,
			verified_by = $2
		WHERE id = $3
	`, now, userID, id)
	return err
}

func (s *service) GenerateAPIKey(ctx context.Context, id string) (string, error) {
	apiKey, err := s.generateNewAPIKey()
	if err != nil {
		return "", err
	}

	encryptedAPIKey, err := s.encrypt.Encrypt([]byte(apiKey))
	if err != nil {
		return "", err
	}

	_, err = s.db.Exec(ctx, `
		UPDATE providers
		SET
			api_key = $1,
			updated_at = $2
		WHERE id = $3
	`, encryptedAPIKey, time.Now(), id)
	if err != nil {
		return "", err
	}

	// Log audit event
	details, err := json.Marshal(map[string]interface{}{
		"provider_type": "",
		"npi":           "",
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal audit event details: %v", err)
	}

	userID := ctx.Value("user_id").(string)
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "GENERATE_API_KEY",
		Resource:    "provider",
		ResourceID:  id,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	return apiKey, nil
}

func (s *service) ValidateAPIKey(ctx context.Context, apiKey string) (*Provider, error) {
	rows, err := s.db.Query(ctx, `
		SELECT
			id,
			type,
			npi,
			tax_id,
			api_key,
			created_at,
			updated_at,
			last_verified,
			verified_by
		FROM providers
		WHERE status = 'ACTIVE'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var provider Provider
		if err := rows.Scan(
			&provider.ID,
			&provider.Type,
			&provider.NPI,
			&provider.TaxID,
			&provider.APIKey,
			&provider.CreatedAt,
			&provider.UpdatedAt,
			&provider.LastVerified,
			&provider.VerifiedBy,
		); err != nil {
			continue
		}

		decryptedKey, err := s.encrypt.Decrypt(provider.APIKey)
		if err != nil {
			continue
		}

		if string(decryptedKey) == apiKey {
			if err := s.decryptProviderData(&provider); err != nil {
				return nil, err
			}
			return &provider, nil
		}
	}

	return nil, ErrUnauthorizedAccess
}

func (s *service) generateNewAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *service) encryptProviderData(provider *Provider) error {
	if provider.TaxID != "" {
		encrypted, err := s.encrypt.Encrypt([]byte(provider.TaxID))
		if err != nil {
			return err
		}
		provider.TaxID = encrypted
	}

	return nil
}

func (s *service) decryptProviderData(provider *Provider) error {
	if provider.TaxID != "" {
		decrypted, err := s.encrypt.Decrypt(provider.TaxID)
		if err != nil {
			return err
		}
		provider.TaxID = string(decrypted)
	}

	return nil
}
