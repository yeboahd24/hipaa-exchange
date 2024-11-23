package provider

import (
	"fmt"
	"strings"
	"time"
)

type ProviderType string

const (
	ProviderTypeHospital   ProviderType = "HOSPITAL"
	ProviderTypeClinic     ProviderType = "CLINIC"
	ProviderTypePhysician  ProviderType = "PHYSICIAN"
	ProviderTypeLaboratory ProviderType = "LABORATORY"
	ProviderTypePharmacy   ProviderType = "PHARMACY"
)

type Certification struct {
	Type       string    `json:"type" bson:"type"`
	Number     string    `json:"number" bson:"number"`
	IssuedBy   string    `json:"issued_by" bson:"issued_by"`
	IssuedDate time.Time `json:"issued_date" bson:"issued_date"`
	ExpiryDate time.Time `json:"expiry_date" bson:"expiry_date"`
	Status     string    `json:"status" bson:"status"`
}

type Address struct {
	Street     string `json:"street" bson:"street"`
	City       string `json:"city" bson:"city"`
	State      string `json:"state" bson:"state"`
	PostalCode string `json:"postal_code" bson:"postal_code"`
	Country    string `json:"country" bson:"country"`
}

type Contact struct {
	Type    string `json:"type" bson:"type"`
	Value   string `json:"value" bson:"value"`
	Primary bool   `json:"primary" bson:"primary"`
}

type Provider struct {
	ID             string          `json:"id" bson:"_id"`
	Type           ProviderType    `json:"type" bson:"type"`
	Name           string          `json:"name" bson:"name"`
	Organization   string          `json:"organization" bson:"organization"`
	NPI            string          `json:"npi" bson:"npi"`       // National Provider Identifier
	TaxID          string          `json:"tax_id" bson:"tax_id"` // Encrypted
	Certifications []Certification `json:"certifications" bson:"certifications"`
	Address        Address         `json:"address" bson:"address"`
	Contacts       []Contact       `json:"contacts" bson:"contacts"`

	// Security and compliance
	Status      string   `json:"status" bson:"status"`
	AccessLevel string   `json:"access_level" bson:"access_level"`
	Specialties []string `json:"specialties" bson:"specialties"`
	DataAccess  []string `json:"data_access" bson:"data_access"` // Types of data this provider can access

	// Integration details
	APIKey    string   `json:"api_key" bson:"api_key"` // Encrypted
	Endpoints []string `json:"endpoints" bson:"endpoints"`
	PublicKey string   `json:"public_key" bson:"public_key"` // For secure data exchange

	// Metadata
	CreatedAt    time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" bson:"updated_at"`
	LastVerified time.Time `json:"last_verified" bson:"last_verified"`
	VerifiedBy   string    `json:"verified_by" bson:"verified_by"`
}

// Sensitive returns a list of fields that contain sensitive information
func (p *Provider) Sensitive() []string {
	return []string{
		"TaxID",
		"APIKey",
	}
}

// Validate performs basic validation of provider data
func (p *Provider) Validate() error {
	if p.Name == "" || p.Type == "" {
		return ErrInvalidProviderData
	}
	if p.NPI == "" {
		return ErrMissingNPI
	}
	if len(p.Certifications) == 0 {
		return ErrMissingCertifications
	}
	return p.validateCertifications()
}

func (p *Provider) validateCertifications() error {
	now := time.Now()
	for _, cert := range p.Certifications {
		if cert.ExpiryDate.Before(now) {
			return ErrExpiredCertification
		}
	}
	return nil
}

// IsActive checks if the provider is active and certified
func (p *Provider) IsActive() bool {
	return p.Status == "ACTIVE" && p.validateCertifications() == nil
}

// CanAccessDataType checks if the provider has permission to access specific data type
func (p *Provider) CanAccessDataType(dataType string) bool {
	for _, access := range p.DataAccess {
		if access == dataType {
			return true
		}
	}
	return false
}

// ParseCertification creates a new Certification from a string representation
// Expected format: "TYPE:NUMBER:ISSUED_BY"
func ParseCertification(certStr string) (Certification, error) {
	parts := strings.Split(certStr, ":")
	if len(parts) < 3 {
		return Certification{}, fmt.Errorf("invalid certification format, expected TYPE:NUMBER:ISSUED_BY, got %s", certStr)
	}

	cert := Certification{
		Type:       strings.TrimSpace(parts[0]),
		Number:     strings.TrimSpace(parts[1]),
		IssuedBy:   strings.TrimSpace(parts[2]),
		IssuedDate: time.Now(),
		ExpiryDate: time.Now().AddDate(2, 0, 0), // Default 2-year expiry
		Status:     "ACTIVE",
	}

	// Basic validation
	if cert.Type == "" || cert.Number == "" || cert.IssuedBy == "" {
		return Certification{}, fmt.Errorf("certification type, number, and issuer are required")
	}

	// Validate certification type
	validTypes := map[string]bool{
		"MEDICAL_LICENSE":         true,
		"BOARD_CERTIFICATION":     true,
		"STATE_LICENSE":           true,
		"DEA_REGISTRATION":        true,
		"SPECIALTY_CERTIFICATION": true,
	}

	if !validTypes[cert.Type] {
		return Certification{}, fmt.Errorf("invalid certification type: %s", cert.Type)
	}

	return cert, nil
}

// ParseCertifications converts a slice of certification strings to Certification objects
func ParseCertifications(certStrings []string) ([]Certification, error) {
	if len(certStrings) == 0 {
		return nil, fmt.Errorf("at least one certification is required")
	}

	certifications := make([]Certification, 0, len(certStrings))
	var errors []string

	for _, certStr := range certStrings {
		cert, err := ParseCertification(certStr)
		if err != nil {
			errors = append(errors, fmt.Sprintf("invalid certification '%s': %v", certStr, err))
			continue
		}
		certifications = append(certifications, cert)
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("certification validation errors: %s", strings.Join(errors, "; "))
	}

	return certifications, nil
}
