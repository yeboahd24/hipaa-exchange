package patient

import (
	"encoding/json"
	"time"
)

type PatientIdentifier struct {
	ID        string    `json:"id" bson:"id"`
	PatientID string    `json:"patient_id" bson:"patient_id"`
	Type      string    `json:"type" bson:"type"`   // e.g., "SSN", "MRN", "Insurance"
	Value     string    `json:"value" bson:"value"` // Encrypted value
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}

type Address struct {
	Street     string `json:"street" bson:"street"`
	City       string `json:"city" bson:"city"`
	State      string `json:"state" bson:"state"`
	PostalCode string `json:"postal_code" bson:"postal_code"`
	Country    string `json:"country" bson:"country"`
}

type PatientContact struct {
	ID        string    `json:"id" bson:"id"`
	PatientID string    `json:"patient_id" bson:"patient_id"`
	Type      string    `json:"type" bson:"type"`   // e.g., "phone", "email"
	Value     string    `json:"value" bson:"value"` // Encrypted value
	IsPrimary bool      `json:"is_primary" bson:"is_primary"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

type Insurance struct {
	Provider     string    `json:"provider" bson:"provider"`
	PolicyNumber string    `json:"policy_number" bson:"policy_number"` // Encrypted
	GroupNumber  string    `json:"group_number" bson:"group_number"`   // Encrypted
	StartDate    time.Time `json:"start_date" bson:"start_date"`
	EndDate      time.Time `json:"end_date,omitempty" bson:"end_date,omitempty"`
}

type Patient struct {
	ID                 string              `json:"id" bson:"_id"`
	Identifiers        []PatientIdentifier `json:"identifiers" bson:"identifiers"`
	FirstName          string              `json:"first_name" bson:"first_name"`
	LastName           string              `json:"last_name" bson:"last_name"`
	DateOfBirth        time.Time           `json:"date_of_birth" bson:"date_of_birth"`
	Gender             string              `json:"gender" bson:"gender"`
	Address            Address             `json:"address" bson:"address"`
	Contacts           []PatientContact    `json:"contacts" bson:"contacts"`
	Insurance          []Insurance         `json:"insurance" bson:"insurance"`

	// Consent and sharing preferences
	DataSharingConsent  bool      `json:"data_sharing_consent" bson:"data_sharing_consent"`
	ConsentDate         time.Time `json:"consent_date" bson:"consent_date"`
	RestrictedProviders []string  `json:"restricted_providers" bson:"restricted_providers"`

	// Metadata
	CreatedAt time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" bson:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" bson:"deleted_at,omitempty"`

	// Patient Status
	Status           string    `json:"status" bson:"status"`

	PrimaryCareProvider string    `json:"primary_care_provider" bson:"primary_care_provider"`

	// Authorized providers
	AuthorizedProviders []string  `json:"authorized_providers" bson:"authorized_providers"`

	// Care team
	CareTeam         []string  `json:"care_team" bson:"care_team"`

	// Created and last modified by
	CreatedBy        string    `json:"created_by" bson:"created_by"`
	LastModifiedBy   string    `json:"last_modified_by" bson:"last_modified_by"`
}

// Implement custom marshaling to handle encryption/decryption
func (p *Patient) MarshalJSON() ([]byte, error) {
	type Alias Patient
	return json.Marshal(&struct {
		*Alias
		DateOfBirth string `json:"date_of_birth"`
	}{
		Alias:       (*Alias)(p),
		DateOfBirth: p.DateOfBirth.Format("2006-01-02"),
	})
}

// Sensitive returns a list of fields that contain sensitive information
func (p *Patient) Sensitive() []string {
	return []string{
		"Identifiers",
		"DateOfBirth",
		"Insurance.PolicyNumber",
		"Insurance.GroupNumber",
		"Contacts.Value",
	}
}

// Validate performs basic validation of patient data
func (p *Patient) Validate() error {
	if p.FirstName == "" || p.LastName == "" {
		return ErrInvalidPatientData
	}
	if p.DateOfBirth.IsZero() {
		return ErrInvalidDateOfBirth
	}
	if len(p.Identifiers) == 0 {
		return ErrMissingIdentifiers
	}
	return nil
}
