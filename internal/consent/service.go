package consent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
	"github.com/mesikahq/hipaa-exchange/internal/audit"
)

var (
	ErrConsentNotFound    = errors.New("consent record not found")
	ErrInvalidConsent     = errors.New("invalid consent data")
	ErrExpiredConsent     = errors.New("consent has expired")
	ErrUnauthorizedAccess = errors.New("unauthorized access to consent data")
)

type ConsentType string

const (
	ConsentTypeDataSharing     ConsentType = "DATA_SHARING"
	ConsentTypeResearch        ConsentType = "RESEARCH"
	ConsentTypeEmergencyAccess ConsentType = "EMERGENCY_ACCESS"
)

type ConsentStatus string

const (
	ConsentStatusActive  ConsentStatus = "ACTIVE"
	ConsentStatusRevoked ConsentStatus = "REVOKED"
	ConsentStatusExpired ConsentStatus = "EXPIRED"
	ConsentStatusPending ConsentStatus = "PENDING"
)

type Consent struct {
	ID             string        `json:"id"`
	PatientID      string        `json:"patient_id"`
	Type           ConsentType   `json:"type"`
	Status         ConsentStatus `json:"status"`
	GrantedTo      []string      `json:"granted_to"`
	Purpose        string        `json:"purpose"`
	StartDate      time.Time     `json:"start_date"`
	EndDate        time.Time     `json:"end_date"`
	Restrictions   []string      `json:"restrictions"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	CreatedBy      string        `json:"created_by"`
	LastModifiedBy string        `json:"last_modified_by"`
	SignedBy       string        `json:"signed_by"`
	SignatureDate  time.Time     `json:"signature_date"`
}

type Service interface {
	Grant(ctx context.Context, consent *Consent) error
	Revoke(ctx context.Context, id string) error
	Get(ctx context.Context, id string) (*Consent, error)
	GetByPatient(ctx context.Context, patientID string) ([]*Consent, error)
	Verify(ctx context.Context, patientID string, providerID string, consentType ConsentType) (bool, error)
	Update(ctx context.Context, consent *Consent) error
}

type service struct {
	db    *pgxpool.Pool
	audit audit.Service
}

func NewService(db *pgxpool.Pool, audit audit.Service) Service {
	return &service{
		db:    db,
		audit: audit,
	}
}

func (s *service) Grant(ctx context.Context, consent *Consent) error {
	if err := s.validateConsent(consent); err != nil {
		return err
	}

	// Set metadata
	now := time.Now()
	consent.CreatedAt = now
	consent.UpdatedAt = now
	consent.Status = ConsentStatusActive

	userID := ctx.Value("user_id").(string)
	consent.CreatedBy = userID
	consent.LastModifiedBy = userID

	// Insert into database
	_, err := s.db.Exec(ctx, `
		INSERT INTO consents (
			id, patient_id, type, status, granted_to, purpose, start_date, end_date, restrictions,
			created_at, updated_at, created_by, last_modified_by, signed_by, signature_date
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)
	`,
		consent.ID, consent.PatientID, consent.Type, consent.Status, consent.GrantedTo, consent.Purpose,
		consent.StartDate, consent.EndDate, consent.Restrictions, consent.CreatedAt, consent.UpdatedAt,
		consent.CreatedBy, consent.LastModifiedBy, consent.SignedBy, consent.SignatureDate,
	)
	if err != nil {
		return err
	}

	// Log audit event
	details, err := json.Marshal(map[string]interface{}{
		"patient_id": consent.PatientID,
		"type":       consent.Type,
		"granted_to": consent.GrantedTo,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal audit log details: %v", err)
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventConsent,
		UserID:      userID,
		Action:      "GRANT",
		Resource:    "consent",
		ResourceID:  consent.ID,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	return nil
}

func (s *service) Revoke(ctx context.Context, id string) error {
	consent, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	userID := ctx.Value("user_id").(string)
	now := time.Now()

	_, err = s.db.Exec(ctx, `
		UPDATE consents SET status = $1, updated_at = $2, last_modified_by = $3 WHERE id = $4
	`,
		ConsentStatusRevoked, now, userID, id,
	)
	if err != nil {
		return err
	}

	// Log audit event
	details, err := json.Marshal(map[string]interface{}{
		"patient_id": consent.PatientID,
		"type":       consent.Type,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal audit log details: %v", err)
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventConsent,
		UserID:      userID,
		Action:      "REVOKE",
		Resource:    "consent",
		ResourceID:  id,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	return nil
}

func (s *service) Get(ctx context.Context, id string) (*Consent, error) {
	var consent Consent
	err := s.db.QueryRow(ctx, `
		SELECT 
			id, patient_id, type, status, granted_to, purpose, start_date, end_date, restrictions,
			created_at, updated_at, created_by, last_modified_by, signed_by, signature_date
		FROM consents WHERE id = $1
	`, id).Scan(
		&consent.ID, &consent.PatientID, &consent.Type, &consent.Status, &consent.GrantedTo, &consent.Purpose,
		&consent.StartDate, &consent.EndDate, &consent.Restrictions, &consent.CreatedAt, &consent.UpdatedAt,
		&consent.CreatedBy, &consent.LastModifiedBy, &consent.SignedBy, &consent.SignatureDate,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, ErrConsentNotFound
		}
		return nil, err
	}

	// Log audit event
	userID := ctx.Value("user_id").(string)
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      userID,
		Action:      "READ",
		Resource:    "consent",
		ResourceID:  id,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return &consent, nil
}

func (s *service) GetByPatient(ctx context.Context, patientID string) ([]*Consent, error) {
	rows, err := s.db.Query(ctx, `
		SELECT 
			id, patient_id, type, status, granted_to, purpose, start_date, end_date, restrictions,
			created_at, updated_at, created_by, last_modified_by, signed_by, signature_date
		FROM consents WHERE patient_id = $1 AND status = $2
	`, patientID, ConsentStatusActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var consents []*Consent
	for rows.Next() {
		var consent Consent
		err := rows.Scan(
			&consent.ID, &consent.PatientID, &consent.Type, &consent.Status, &consent.GrantedTo, &consent.Purpose,
			&consent.StartDate, &consent.EndDate, &consent.Restrictions, &consent.CreatedAt, &consent.UpdatedAt,
			&consent.CreatedBy, &consent.LastModifiedBy, &consent.SignedBy, &consent.SignatureDate,
		)
		if err != nil {
			return nil, err
		}
		consents = append(consents, &consent)
	}

	return consents, nil
}

func (s *service) Verify(ctx context.Context, patientID string, providerID string, consentType ConsentType) (bool, error) {
	var consent Consent
	err := s.db.QueryRow(ctx, `
		SELECT 
			id, patient_id, type, status, granted_to, purpose, start_date, end_date, restrictions,
			created_at, updated_at, created_by, last_modified_by, signed_by, signature_date
		FROM consents WHERE patient_id = $1 AND type = $2 AND status = $3 AND granted_to @> $4 AND end_date > $5
	`, patientID, consentType, ConsentStatusActive, []string{providerID}, time.Now()).Scan(
		&consent.ID, &consent.PatientID, &consent.Type, &consent.Status, &consent.GrantedTo, &consent.Purpose,
		&consent.StartDate, &consent.EndDate, &consent.Restrictions, &consent.CreatedAt, &consent.UpdatedAt,
		&consent.CreatedBy, &consent.LastModifiedBy, &consent.SignedBy, &consent.SignatureDate,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return false, nil
		}
		return false, err
	}

	// Check restrictions
	for _, restriction := range consent.Restrictions {
		if restriction == providerID {
			return false, nil
		}
	}

	// Log verification attempt
	userID := ctx.Value("user_id").(string)
	details, err := json.Marshal(map[string]interface{}{
		"patient_id":  patientID,
		"provider_id": providerID,
		"type":        consentType,
		"granted":     true,
	})
	if err != nil {
		return false, fmt.Errorf("failed to marshal audit log details: %v", err)
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventConsent,
		UserID:      userID,
		Action:      "VERIFY",
		Resource:    "consent",
		ResourceID:  consent.ID,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	return true, nil
}

func (s *service) Update(ctx context.Context, consent *Consent) error {
	query := `
		UPDATE consents 
		SET 
			granted_to = $2, 
			purpose = $3, 
			type = $4, 
			end_date = $5, 
			status = $6, 
			updated_at = $7
		WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.db.Exec(ctx, query,
		consent.ID,
		pq.Array(consent.GrantedTo),
		consent.Purpose,
		consent.Type,
		consent.EndDate,
		consent.Status,
		time.Now().UTC(),
	)

	if err != nil {
		return fmt.Errorf("failed to update consent: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return ErrConsentNotFound
	}

	// Log the update for audit purposes
	details, err := json.Marshal(map[string]interface{}{
		"patient_id": consent.PatientID,
		"type":       consent.Type,
		"granted_to": consent.GrantedTo,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal audit log details: %v", err)
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventConsent,
		UserID:      consent.LastModifiedBy,
		Action:      "UPDATE",
		Resource:    "consent",
		ResourceID:  consent.ID,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	return nil
}

func (s *service) validateConsent(consent *Consent) error {
	if consent.PatientID == "" || consent.Type == "" {
		return ErrInvalidConsent
	}

	if consent.EndDate.Before(time.Now()) {
		return ErrExpiredConsent
	}

	if len(consent.GrantedTo) == 0 {
		return ErrInvalidConsent
	}

	return nil
}
