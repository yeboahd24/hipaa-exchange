package patient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5"

	"github.com/mesikahq/hipaa-exchange/internal/audit"
	"github.com/mesikahq/hipaa-exchange/internal/encryption"
	"github.com/mesikahq/hipaa-exchange/internal/provider"
)

// EmergencyAccessKey is a context key used to indicate emergency access to patient data
var EmergencyAccessKey = struct{}{}

// BreakGlassKey is a context key for break glass access
var BreakGlassKey = struct{}{}

var (
	ErrPatientNotFound    = errors.New("patient not found")
	ErrInvalidPatientData = errors.New("invalid patient data")
	ErrInvalidDateOfBirth = errors.New("invalid date of birth")
	ErrMissingIdentifiers = errors.New("missing patient identifiers")
	ErrUnauthorizedAccess = errors.New("unauthorized access to patient data")
)

type Service interface {
	Create(ctx context.Context, patient *Patient) error
	Get(ctx context.Context, id string) (*Patient, error)
	Update(ctx context.Context, patient *Patient) error
	Delete(ctx context.Context, id string) error
	Search(ctx context.Context, query map[string]interface{}) ([]*Patient, error)
	GetHistory(ctx context.Context, id string) ([]audit.AuditEvent, error)
}

type service struct {
	db              *pgxpool.Pool
	encrypt         encryption.Service
	audit           audit.Service
	providerService provider.Service
}

func NewService(db *pgxpool.Pool, encrypt encryption.Service, audit audit.Service, providerService provider.Service) Service {
	return &service{
		db:              db,
		encrypt:         encrypt,
		audit:           audit,
		providerService: providerService,
	}
}

func (s *service) Create(ctx context.Context, patient *Patient) error {
	if err := patient.Validate(); err != nil {
		return err
	}

	// Encrypt sensitive fields
	if err := s.encryptPatientData(patient); err != nil {
		return err
	}

	// Set metadata
	now := time.Now()
	patient.CreatedAt = now
	patient.UpdatedAt = now

	userID := ctx.Value("user_id").(string)
	patient.CreatedBy = userID
	patient.LastModifiedBy = userID

	// Set default status
	patient.Status = "ACTIVE"

	// Insert into database
	_, err := s.db.Exec(ctx, "INSERT INTO patients (id, created_at, updated_at, created_by, last_modified_by, identifiers, contacts, insurance, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", patient.ID, patient.CreatedAt, patient.UpdatedAt, patient.CreatedBy, patient.LastModifiedBy, patient.Identifiers, patient.Contacts, patient.Insurance, patient.Status)
	if err != nil {
		return err
	}

	// Log audit event
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "CREATE",
		Resource:    "patient",
		ResourceID:  patient.ID,
		Status:      "success",
		Sensitivity: "PHI",
	})

	return nil
}

func (s *service) Get(ctx context.Context, id string) (*Patient, error) {
	var patient Patient
	err := s.db.QueryRow(ctx, "SELECT * FROM patients WHERE id = $1", id).Scan(&patient)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrPatientNotFound
		}
		return nil, err
	}

	// Check access restrictions
	userID := ctx.Value("user_id").(string)
	if !s.canAccessPatient(ctx, userID, &patient) {
		return nil, ErrUnauthorizedAccess
	}

	// Decrypt sensitive fields
	if err := s.decryptPatientData(&patient); err != nil {
		return nil, err
	}

	// Log audit event
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      userID,
		Action:      "READ",
		Resource:    "patient",
		ResourceID:  patient.ID,
		Status:      "success",
		Sensitivity: "PHI",
	})

	return &patient, nil
}

func (s *service) Update(ctx context.Context, patient *Patient) error {
	if err := patient.Validate(); err != nil {
		return err
	}

	// Check access restrictions
	userID := ctx.Value("user_id").(string)
	if !s.canAccessPatient(ctx, userID, patient) {
		return ErrUnauthorizedAccess
	}

	// Encrypt sensitive fields
	if err := s.encryptPatientData(patient); err != nil {
		return err
	}

	// Update metadata
	patient.UpdatedAt = time.Now()
	patient.LastModifiedBy = userID

	// Update in database
	_, err := s.db.Exec(ctx, "UPDATE patients SET updated_at = $1, last_modified_by = $2, identifiers = $3, contacts = $4, insurance = $5, status = $6 WHERE id = $7", patient.UpdatedAt, patient.LastModifiedBy, patient.Identifiers, patient.Contacts, patient.Insurance, patient.Status, patient.ID)
	if err != nil {
		return err
	}

	// Log audit event
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "UPDATE",
		Resource:    "patient",
		ResourceID:  patient.ID,
		Status:      "success",
		Sensitivity: "PHI",
	})

	return nil
}

func (s *service) Delete(ctx context.Context, id string) error {
	// Check if patient exists and user has access
	_, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	// Delete from database
	_, err = s.db.Exec(ctx, "DELETE FROM patients WHERE id = $1", id)
	if err != nil {
		return err
	}

	// Log audit event
	userID := ctx.Value("user_id").(string)
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventDelete,
		UserID:      userID,
		Action:      "DELETE",
		Resource:    "patient",
		ResourceID:  id,
		Status:      "success",
		Sensitivity: "PHI",
	})

	return nil
}

func (s *service) Search(ctx context.Context, query map[string]interface{}) ([]*Patient, error) {
	baseQuery := `
		SELECT 
			id, first_name, last_name, date_of_birth, gender, 
			data_sharing_consent, consent_date, created_at, updated_at, deleted_at 
		FROM patients 
		WHERE deleted_at IS NULL`
	args := make([]interface{}, 0)
	paramCount := 1

	// Build query conditions
	conditions := make([]string, 0)
	for key, value := range query {
		conditions = append(conditions, fmt.Sprintf("%s = $%d", key, paramCount))
		args = append(args, value)
		paramCount++
	}

	if len(conditions) > 0 {
		baseQuery += " AND " + strings.Join(conditions, " AND ")
	}

	// Execute query
	rows, err := s.db.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute search query: %w", err)
	}
	defer rows.Close()

	var patients []*Patient
	for rows.Next() {
		var patient Patient
		err := rows.Scan(
			&patient.ID,
			&patient.FirstName,
			&patient.LastName,
			&patient.DateOfBirth,
			&patient.Gender,
			&patient.DataSharingConsent,
			&patient.ConsentDate,
			&patient.CreatedAt,
			&patient.UpdatedAt,
			&patient.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan patient row: %w", err)
		}

		// Check access restrictions
		userID := ctx.Value("user_id").(string)
		if s.canAccessPatient(ctx, userID, &patient) {
			// Load patient identifiers and contacts
			if err := s.loadPatientRelations(ctx, &patient); err != nil {
				return nil, fmt.Errorf("failed to load patient relations: %w", err)
			}

			// Decrypt sensitive data
			if err := s.decryptPatientData(&patient); err != nil {
				return nil, fmt.Errorf("failed to decrypt patient data: %w", err)
			}

			patients = append(patients, &patient)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over patient rows: %w", err)
	}

	return patients, nil
}

func (s *service) loadPatientRelations(ctx context.Context, patient *Patient) error {
	// Load identifiers
	identRows, err := s.db.Query(ctx, `
		SELECT id, patient_id, type, value, created_at 
		FROM patient_identifiers 
		WHERE patient_id = $1`,
		patient.ID)
	if err != nil {
		return fmt.Errorf("failed to query patient identifiers: %w", err)
	}
	defer identRows.Close()

	patient.Identifiers = make([]PatientIdentifier, 0)
	for identRows.Next() {
		var identifier PatientIdentifier
		if err := identRows.Scan(
			&identifier.ID,
			&identifier.PatientID,
			&identifier.Type,
			&identifier.Value,
			&identifier.CreatedAt,
		); err != nil {
			return fmt.Errorf("failed to scan identifier row: %w", err)
		}
		patient.Identifiers = append(patient.Identifiers, identifier)
	}

	// Load contacts
	contactRows, err := s.db.Query(ctx, `
		SELECT id, patient_id, type, value, is_primary, created_at, updated_at 
		FROM patient_contacts 
		WHERE patient_id = $1`,
		patient.ID)
	if err != nil {
		return fmt.Errorf("failed to query patient contacts: %w", err)
	}
	defer contactRows.Close()

	patient.Contacts = make([]PatientContact, 0)
	for contactRows.Next() {
		var contact PatientContact
		if err := contactRows.Scan(
			&contact.ID,
			&contact.PatientID,
			&contact.Type,
			&contact.Value,
			&contact.IsPrimary,
			&contact.CreatedAt,
			&contact.UpdatedAt,
		); err != nil {
			return fmt.Errorf("failed to scan contact row: %w", err)
		}
		patient.Contacts = append(patient.Contacts, contact)
	}

	return nil
}

func (s *service) GetHistory(ctx context.Context, id string) ([]audit.AuditEvent, error) {
	// Check if patient exists and user has access
	if _, err := s.Get(ctx, id); err != nil {
		return nil, err
	}

	filters := map[string]interface{}{
		"resource":    "patient",
		"resource_id": id,
	}

	events, err := s.audit.QueryEvents(ctx, filters, 0, 100)
	if err != nil {
		return nil, err
	}

	return events, nil
}

func (s *service) encryptPatientData(patient *Patient) error {
	for i := range patient.Identifiers {
		encrypted, err := s.encrypt.Encrypt([]byte(patient.Identifiers[i].Value))
		if err != nil {
			return err
		}
		patient.Identifiers[i].Value = encrypted
	}

	for i := range patient.Contacts {
		encrypted, err := s.encrypt.Encrypt([]byte(patient.Contacts[i].Value))
		if err != nil {
			return err
		}
		patient.Contacts[i].Value = encrypted
	}

	for i := range patient.Insurance {
		policyEncrypted, err := s.encrypt.Encrypt([]byte(patient.Insurance[i].PolicyNumber))
		if err != nil {
			return err
		}
		patient.Insurance[i].PolicyNumber = policyEncrypted

		groupEncrypted, err := s.encrypt.Encrypt([]byte(patient.Insurance[i].GroupNumber))
		if err != nil {
			return err
		}
		patient.Insurance[i].GroupNumber = groupEncrypted
	}

	return nil
}

func (s *service) decryptPatientData(patient *Patient) error {
	for i := range patient.Identifiers {
		decrypted, err := s.encrypt.Decrypt(patient.Identifiers[i].Value)
		if err != nil {
			return err
		}
		patient.Identifiers[i].Value = string(decrypted)
	}

	for i := range patient.Contacts {
		decrypted, err := s.encrypt.Decrypt(patient.Contacts[i].Value)
		if err != nil {
			return err
		}
		patient.Contacts[i].Value = string(decrypted)
	}

	for i := range patient.Insurance {
		policyDecrypted, err := s.encrypt.Decrypt(patient.Insurance[i].PolicyNumber)
		if err != nil {
			return err
		}
		patient.Insurance[i].PolicyNumber = string(policyDecrypted)

		groupDecrypted, err := s.encrypt.Decrypt(patient.Insurance[i].GroupNumber)
		if err != nil {
			return err
		}
		patient.Insurance[i].GroupNumber = string(groupDecrypted)
	}

	return nil
}

func (s *service) canAccessPatient(ctx context.Context, userID string, patient *Patient) bool {
	// First check restricted providers list (deny list)
	for _, restrictedProvider := range patient.RestrictedProviders {
		if restrictedProvider == userID {
			s.audit.LogEvent(ctx, &audit.AuditEvent{
				EventType:   audit.EventAccess,
				UserID:      userID,
				Action:      "DENY",
				Resource:    "patient",
				ResourceID:  patient.ID,
				Status:      "failure",
				Sensitivity: "PHI",
				Details: func() json.RawMessage {
					details := map[string]interface{}{
						"reason": "provider_restricted",
					}
					detailsJSON, _ := json.Marshal(details)
					return json.RawMessage(detailsJSON)
				}(),
			})
			return false
		}
	}

	// Get provider details
	provider, err := s.providerService.Get(ctx, userID)
	if err != nil {
		s.audit.LogEvent(ctx, &audit.AuditEvent{
			EventType:   audit.EventAccess,
			UserID:      userID,
			Action:      "DENY",
			Resource:    "patient",
			ResourceID:  patient.ID,
			Status:      "failure",
			Sensitivity: "PHI",
			Details: func() json.RawMessage {
				details := map[string]interface{}{
					"reason": "provider_not_found",
				}
				detailsJSON, _ := json.Marshal(details)
				return json.RawMessage(detailsJSON)
			}(),
		})
		return false
	}

	// Check if provider is active and has valid certifications
	if !provider.IsActive() {
		s.audit.LogEvent(ctx, &audit.AuditEvent{
			EventType:   audit.EventAccess,
			UserID:      userID,
			Action:      "DENY",
			Resource:    "patient",
			ResourceID:  patient.ID,
			Status:      "failure",
			Sensitivity: "PHI",
			Details: func() json.RawMessage {
				details := map[string]interface{}{
					"reason": "inactive_provider",
				}
				detailsJSON, _ := json.Marshal(details)
				return json.RawMessage(detailsJSON)
			}(),
		})
		return false
	}

	// Check for emergency access flag
	if ctx.Value(EmergencyAccessKey) != nil {
		s.audit.LogEvent(ctx, &audit.AuditEvent{
			EventType:   audit.EventEmergencyAccess,
			UserID:      userID,
			Action:      "GRANT",
			Resource:    "patient",
			ResourceID:  patient.ID,
			Status:      "success",
			Sensitivity: "PHI",
			Details: func() json.RawMessage {
				details := map[string]interface{}{
					"reason": "emergency_protocol",
				}
				detailsJSON, _ := json.Marshal(details)
				return json.RawMessage(detailsJSON)
			}(),
		})
		return true
	}

	// Check provider-patient relationship
	// If provider is in the care team
	if containsString(patient.CareTeam, userID) {
		s.audit.LogEvent(ctx, &audit.AuditEvent{
			EventType:   audit.EventAccess,
			UserID:      userID,
			Action:      "GRANT",
			Resource:    "patient",
			ResourceID:  patient.ID,
			Status:      "success",
			Sensitivity: "PHI",
			Details: func() json.RawMessage {
				details := map[string]interface{}{
					"reason": "direct_care_provider",
				}
				detailsJSON, _ := json.Marshal(details)
				return json.RawMessage(detailsJSON)
			}(),
		})
		return true
	}

	// Check if provider has explicit consent
	if containsString(patient.AuthorizedProviders, userID) {
		s.audit.LogEvent(ctx, &audit.AuditEvent{
			EventType:   audit.EventAccess,
			UserID:      userID,
			Action:      "GRANT",
			Resource:    "patient",
			ResourceID:  patient.ID,
			Status:      "success",
			Sensitivity: "PHI",
			Details: func() json.RawMessage {
				details := map[string]interface{}{
					"reason": "authorized_provider",
				}
				detailsJSON, _ := json.Marshal(details)
				return json.RawMessage(detailsJSON)
			}(),
		})
		return true
	}

	// Check break-glass procedure
	breakGlass := ctx.Value(BreakGlassKey)
	if breakGlass != nil {
		if reason, ok := breakGlass.(string); ok && reason != "" {
			s.audit.LogEvent(ctx, &audit.AuditEvent{
				EventType:   audit.EventTypeBreakGlass,
				UserID:      userID,
				Action:      "GRANT",
				Resource:    "patient",
				ResourceID:  patient.ID,
				Status:      "success",
				Sensitivity: "PHI",
				Details: func() json.RawMessage {
					details := map[string]interface{}{
						"reason": reason,
					}
					detailsJSON, _ := json.Marshal(details)
					return json.RawMessage(detailsJSON)
				}(),
			})
			return true
		}
	}

	// Default deny if no access conditions are met
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      userID,
		Action:      "DENY",
		Resource:    "patient",
		ResourceID:  patient.ID,
		Status:      "failure",
		Sensitivity: "PHI",
		Details: func() json.RawMessage {
			details := map[string]interface{}{
				"reason": "no_access_granted",
			}
			detailsJSON, _ := json.Marshal(details)
			return json.RawMessage(detailsJSON)
		}(),
	})
	return false
}

// Helper function to check if a string exists in a slice
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
