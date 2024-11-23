package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mesikahq/hipaa-exchange/internal/audit"
	"github.com/mesikahq/hipaa-exchange/internal/auth"
	"github.com/mesikahq/hipaa-exchange/internal/careplan"
	"github.com/mesikahq/hipaa-exchange/internal/consent"
	"github.com/mesikahq/hipaa-exchange/internal/patient"
	"github.com/mesikahq/hipaa-exchange/internal/provider"
)

var (
	ErrConsentNotFound     = errors.New("consent not found")
	ErrInvalidConsent      = errors.New("invalid consent")
	ErrPatientNotFound     = errors.New("patient not found")
	ErrInvalidPatient      = errors.New("invalid patient")
	ErrProviderNotFound    = errors.New("provider not found")
	ErrInvalidProvider     = errors.New("invalid provider")
	ErrCarePlanNotFound    = errors.New("care plan not found")
	ErrInvalidCarePlan     = errors.New("invalid care plan")
	ErrAuditLogNotFound    = errors.New("audit log not found")
	ErrInvalidAuditLog     = errors.New("invalid audit log")
	ErrUserNotFound        = errors.New("user not found")
	ErrInvalidUser         = errors.New("invalid user")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrTokenExpired        = errors.New("token has expired")
	ErrInvalidToken        = errors.New("invalid token")
	ErrMFATokenRequired    = errors.New("MFA token is required")
	ErrMFATokenInvalid     = errors.New("MFA token is invalid")
	ErrMFATokenExpired     = errors.New("MFA token has expired")
	ErrMFATokenAlreadyUsed = errors.New("MFA token has already been used")
)

type Handler struct {
	authService     auth.Service
	patientService  patient.Service
	providerService provider.Service
	consentService  consent.Service
	carePlanService careplan.Service
	auditService    audit.Service
}

func NewHandler(
	authService auth.Service,
	patientService patient.Service,
	providerService provider.Service,
	consentService consent.Service,
	carePlanService careplan.Service,
	auditService audit.Service,
) *Handler {
	return &Handler{
		authService:     authService,
		patientService:  patientService,
		providerService: providerService,
		consentService:  consentService,
		carePlanService: carePlanService,
		auditService:    auditService,
	}
}

// Authentication Handlers

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginWithEmailRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Failed to bind JSON: %v", err)
		log.Printf("Request body: %v", c.Request.Body)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Login attempt for user: %s with password length: %d", req.Username, len(req.Password))

	token, err := h.authService.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, ErrMFATokenRequired) {
			c.JSON(http.StatusOK, gin.H{
				"message":      "MFA required",
				"token":        token,
				"mfa_required": true,
			})
			return
		}
		log.Printf("Login failed for user %s: %v", req.Username, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (h *Handler) LoginWithEmail(c *gin.Context) {
	var req LoginWithEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Login attempt for email: %s", req.Email)

	response, err := h.authService.LoginWithEmail(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		log.Printf("Login failed for email %s: %v", req.Email, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

type ValidateMFARequest struct {
	Code string `json:"code" binding:"required"`
}

func (h *Handler) ValidateMFA(c *gin.Context) {
	var req ValidateMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("user_id")
	if err := h.authService.ValidateMFA(c.Request.Context(), userID, req.Code); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA validated successfully"})
}

// RegisterUserRequest represents the request body for user registration
type RegisterUserRequest struct {
	Username string   `json:"username" binding:"required"`
	Email    string   `json:"email" binding:"required,email"`
	Password string   `json:"password" binding:"required"`
	Roles    []string `json:"roles" binding:"required"`
}

// RegisterUser handles user registration
func (h *Handler) RegisterUser(c *gin.Context) {
	var req RegisterUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate roles
	validRoles := map[string]bool{
		"admin":            true,
		"provider_admin":   true,
		"provider":         true,
		"care_coordinator": true,
	}

	for _, role := range req.Roles {
		if !validRoles[role] {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       fmt.Sprintf("invalid role: %s", role),
				"valid_roles": []string{"admin", "provider_admin", "provider", "care_coordinator"},
			})
			return
		}
	}

	// Register user
	user, err := h.authService.Register(c.Request.Context(), req.Username, req.Email, req.Password, req.Roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"roles":    user.Roles,
	})
}

// ListUsers retrieves a list of all users
func (h *Handler) ListUsers(c *gin.Context) {
	ctx := c.Request.Context()
	users, err := h.authService.ListUsers(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
		return
	}

	c.JSON(http.StatusOK, users)
}

// UpdateUserRequest represents the request body for updating a user
type UpdateUserRequest struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

// UpdateUser handles updating a user's information
func (h *Handler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Use authService to update the user
	// Note: You might need to implement this method in your auth.Service
	err := h.authService.UpdateUser(c.Request.Context(), userID, req.Username, req.Roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// DeleteUser handles deactivating a user by their ID
func (h *Handler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	ctx := context.Background()
	err := h.authService.DeactivateUser(ctx, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to deactivate user: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deactivated successfully"})
}

// Logout handles user logout by invalidating the current token
func (h *Handler) Logout(c *gin.Context) {
	// Extract the token from the Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No authorization token provided"})
		return
	}

	// Remove "Bearer " prefix
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate the token first to ensure it's a valid token
	claims, err := h.authService.ValidateToken(c.Request.Context(), tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// TODO: Implement token blacklisting or invalidation mechanism
	// This might involve storing the token in a blacklist or database
	// For now, we'll just return a successful logout response
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
		"user_id": claims.UserID,
	})
}

// GetUserProfile retrieves the current user's profile information
func (h *Handler) GetUserProfile(c *gin.Context) {
	// Get the current user's ID from the authentication context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Retrieve user details using the auth service
	user, err := h.authService.GetUserByID(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user profile"})
		return
	}

	// Return user profile information, excluding sensitive details like password
	c.JSON(http.StatusOK, gin.H{
		"username": user.Username,
		"roles":    user.Roles,
	})
}

// UpdateUserProfileRequest represents the request body for updating a user's profile
type UpdateUserProfileRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email" binding:"omitempty,email"`
	// Add other profile-related fields as needed
}

// UpdateUserProfile handles updating the current user's profile information
func (h *Handler) UpdateUserProfile(c *gin.Context) {
	// Get the authenticated user's ID
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Parse the request body
	var req UpdateUserProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update the user profile using the auth service
	// Note: You might need to modify your auth service to support profile updates
	updatedUser, err := h.authService.UpdateUserProfile(c.Request.Context(), userID.(string), req.FirstName, req.LastName, req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user profile"})
		return
	}

	c.JSON(http.StatusOK, updatedUser)
}

// Provider Handlers

type RegisterProviderRequest struct {
	Name           string   `json:"name" binding:"required"`
	Type           string   `json:"type" binding:"required"`
	NPI            string   `json:"npi" binding:"required"`
	TaxID          string   `json:"tax_id" binding:"required"`
	Address        string   `json:"address" binding:"required"`
	Certifications []string `json:"certifications" binding:"required"`
}

func (h *Handler) RegisterProvider(c *gin.Context) {
	var req RegisterProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Parse and validate certifications
	certifications, err := provider.ParseCertifications(req.Certifications)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   fmt.Sprintf("invalid certifications: %v", err),
			"details": "Expected format for each certification: 'TYPE:NUMBER:ISSUED_BY' where TYPE must be one of: MEDICAL_LICENSE, BOARD_CERTIFICATION, STATE_LICENSE, DEA_REGISTRATION, SPECIALTY_CERTIFICATION",
		})
		return
	}

	provider := &provider.Provider{
		Name:  req.Name,
		Type:  provider.ProviderType(req.Type),
		NPI:   req.NPI,
		TaxID: req.TaxID,
		Address: provider.Address{
			Street: req.Address, // Assuming the full address is in Street
		},
		Certifications: certifications,
	}

	if err := h.providerService.Register(c.Request.Context(), provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, provider)
}

func (h *Handler) GetProvider(c *gin.Context) {
	id := c.Param("id")
	provider, err := h.providerService.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, provider)
}

// ListProviders retrieves a list of all providers
func (h *Handler) ListProviders(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Use an empty query to retrieve all active providers
	providers, err := h.providerService.Search(ctx, map[string]interface{}{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve providers", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, providers)
}

type UpdateProviderRequest struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	NPI            string   `json:"npi"`
	TaxID          string   `json:"tax_id"`
	Address        string   `json:"address"`
	Certifications []string `json:"certifications"`
}

// UpdateProvider handles updating a provider's information
func (h *Handler) UpdateProvider(c *gin.Context) {
	providerID := c.Param("id")
	if providerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Provider ID is required"})
		return
	}

	var req UpdateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Fetch existing provider to update
	ctx := c.Request.Context()
	existingProvider, err := h.providerService.Get(ctx, providerID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
		return
	}

	// Update provider fields
	if req.Name != "" {
		existingProvider.Name = req.Name
	}
	if req.Type != "" {
		providerType := provider.ProviderType(req.Type)
		switch providerType {
		case provider.ProviderTypeHospital,
			provider.ProviderTypeClinic,
			provider.ProviderTypePhysician,
			provider.ProviderTypeLaboratory,
			provider.ProviderTypePharmacy:
			existingProvider.Type = providerType
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider type"})
			return
		}
	}
	if req.NPI != "" {
		existingProvider.NPI = req.NPI
	}
	if req.TaxID != "" {
		existingProvider.TaxID = req.TaxID
	}
	if req.Address != "" {
		// Parse the address string into a structured Address
		addressParts := strings.Split(req.Address, ",")
		if len(addressParts) >= 1 {
			existingProvider.Address.Street = strings.TrimSpace(addressParts[0])
		}
		if len(addressParts) >= 2 {
			cityStateZip := strings.TrimSpace(addressParts[1])
			cityStateParts := strings.Split(cityStateZip, " ")
			if len(cityStateParts) >= 3 {
				existingProvider.Address.City = cityStateParts[0]
				existingProvider.Address.State = cityStateParts[1]
				existingProvider.Address.PostalCode = cityStateParts[2]
			}
		}
		if len(addressParts) >= 3 {
			existingProvider.Address.Country = strings.TrimSpace(addressParts[2])
		}
	}
	if len(req.Certifications) > 0 {
		certifications, err := provider.ParseCertifications(req.Certifications)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certification format"})
			return
		}
		existingProvider.Certifications = certifications
	}

	// Update provider in the database
	if err := h.providerService.Update(ctx, existingProvider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update provider"})
		return
	}

	c.JSON(http.StatusOK, existingProvider)
}

// DeactivateProvider handles deactivating a provider by their ID
func (h *Handler) DeactivateProvider(c *gin.Context) {
	providerID := c.Param("id")
	if providerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Provider ID is required"})
		return
	}

	err := h.providerService.Deactivate(c.Request.Context(), providerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deactivate provider", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Provider deactivated successfully"})
}

// Patient Handlers

type RegisterPatientRequest struct {
	FirstName   string `json:"first_name" binding:"required"`
	LastName    string `json:"last_name" binding:"required"`
	DOB         string `json:"dob" binding:"required"`
	SSN         string `json:"ssn" binding:"required"`
	Address     string `json:"address" binding:"required"`
	PhoneNumber string `json:"phone_number" binding:"required"`
	Email       string `json:"email" binding:"required,email"`
}

func (h *Handler) RegisterPatient(c *gin.Context) {
	var req RegisterPatientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dob, err := time.Parse("2006-01-02", req.DOB)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date of birth format. Use YYYY-MM-DD"})
		return
	}

	patient := &patient.Patient{
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		DateOfBirth: dob,
		Identifiers: []patient.PatientIdentifier{
			{
				Type:  "SSN",
				Value: req.SSN,
			},
		},
		Address: patient.Address{
			Street: req.Address, // Assuming the full address is in Street
		},
		Contacts: []patient.PatientContact{
			{
				Type:     "email",
				Value:    req.Email,
				IsPrimary: true,
			},
			{
				Type:     "phone",
				Value:    req.PhoneNumber,
				IsPrimary: true,
			},
		},
	}

	if err := h.patientService.Create(c.Request.Context(), patient); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, patient)
}

func (h *Handler) GetPatient(c *gin.Context) {
	id := c.Param("id")
	patient, err := h.patientService.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, patient)
}

// ListPatients retrieves a list of patients
func (h *Handler) ListPatients(c *gin.Context) {
	ctx := c.Request.Context()
	patients, err := h.patientService.Search(ctx, map[string]interface{}{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve patients",
			"message": "An error occurred while fetching the patient list",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": patients,
		"message": "Successfully retrieved patients",
	})
}

type UpdatePatientRequest struct {
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	DateOfBirth string `json:"date_of_birth"`
	SSN         string `json:"ssn"`
	Address     string `json:"address"`
	PhoneNumber string `json:"phone_number"`
	Email       string `json:"email" binding:"omitempty,email"`
}

// UpdatePatient handles updating a patient's information
func (h *Handler) UpdatePatient(c *gin.Context) {
	patientID := c.Param("id")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Patient ID is required"})
		return
	}

	var req UpdatePatientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dob, err := time.Parse("2006-01-02", req.DateOfBirth)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date of birth format. Use YYYY-MM-DD"})
		return
	}

	patientToUpdate := &patient.Patient{
		ID:          patientID,
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		DateOfBirth: dob,
		Identifiers: []patient.PatientIdentifier{
			{
				Type:  "SSN",
				Value: req.SSN,
			},
		},
		Address: patient.Address{
			Street: req.Address,
		},
		Contacts: []patient.PatientContact{
			{
				Type:     "phone",
				Value:    req.PhoneNumber,
				IsPrimary: true,
			},
			{
				Type:     "email",
				Value:    req.Email,
				IsPrimary: true,
			},
		},
	}

	err = h.patientService.Update(c.Request.Context(), patientToUpdate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, patientToUpdate)
}

// DeletePatient handles deleting a patient by their ID
func (h *Handler) DeletePatient(c *gin.Context) {
	patientID := c.Param("id")

	ctx := c.Request.Context()
	err := h.patientService.Delete(ctx, patientID)
	if err != nil {
		if errors.Is(err, ErrPatientNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Patient not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete patient"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Patient deleted successfully"})
}

// Consent Handlers

type CreateConsentRequest struct {
	PatientID   string   `json:"patient_id" binding:"required"`
	ProviderIDs []string `json:"provider_ids" binding:"required"`
	Purpose     string   `json:"purpose" binding:"required"`
	Type        string   `json:"type" binding:"required,oneof=DATA_SHARING RESEARCH EMERGENCY_ACCESS"`
	EndDate     string   `json:"expires_at" binding:"required"`
}

func (h *Handler) CreateConsent(c *gin.Context) {
	var req CreateConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	endDate, err := time.Parse(time.RFC3339, req.EndDate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format. Use RFC3339 format (e.g., 2023-12-31T23:59:59Z)"})
		return
	}

	consent := &consent.Consent{
		PatientID: req.PatientID,
		GrantedTo: req.ProviderIDs,
		Purpose:   req.Purpose,
		Type:      consent.ConsentType(req.Type),
		EndDate:   endDate,
	}

	if err := h.consentService.Grant(c.Request.Context(), consent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, consent)
}

func (h *Handler) VerifyConsent(c *gin.Context) {
	patientID := c.Query("patient_id")
	providerID := c.Query("provider_id")
	dataType := c.Query("data_type")

	if patientID == "" || providerID == "" || dataType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required parameters"})
		return
	}

	valid, err := h.consentService.Verify(c.Request.Context(), patientID, providerID, consent.ConsentType(dataType))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": valid})
}

func (h *Handler) GetConsents(c *gin.Context) {
	ctx := c.Request.Context()
	patientID := c.Query("patient_id")

	var consents []*consent.Consent
	var err error

	if patientID != "" {
		// If patient_id is provided, fetch consents for that patient
		consents, err = h.consentService.GetByPatient(ctx, patientID)
	} else {
		// If no patient_id is provided, return an error or implement a method to get all consents
		c.JSON(http.StatusBadRequest, gin.H{"error": "patient_id is required"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, consents)
}

func (h *Handler) GetConsent(c *gin.Context) {
	ctx := c.Request.Context()
	consentID := c.Param("id")

	// Validate consent ID
	if consentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "consent ID is required"})
		return
	}

	// Fetch the specific consent
	consent, err := h.consentService.Get(ctx, consentID)
	if err != nil {
		if errors.Is(err, ErrConsentNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Consent not found"})
		} else if errors.Is(err, ErrInvalidConsent) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid consent"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, consent)
}

type UpdateConsentRequest struct {
	ProviderIDs []string `json:"provider_ids"`
	Purpose     string   `json:"purpose"`
	Type        string   `json:"type" binding:"omitempty,oneof=DATA_SHARING RESEARCH EMERGENCY_ACCESS"`
	EndDate     string   `json:"expires_at"`
	Status      string   `json:"status" binding:"omitempty,oneof=ACTIVE REVOKED EXPIRED PENDING"`
}

func (h *Handler) UpdateConsent(c *gin.Context) {
	ctx := c.Request.Context()
	consentID := c.Param("id")

	// Validate consent ID
	if consentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "consent ID is required"})
		return
	}

	var req UpdateConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Fetch the existing consent to update
	existingConsent, err := h.consentService.Get(ctx, consentID)
	if err != nil {
		if errors.Is(err, ErrConsentNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Consent not found"})
		} else if errors.Is(err, ErrInvalidConsent) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid consent"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Update consent fields if provided
	if len(req.ProviderIDs) > 0 {
		existingConsent.GrantedTo = req.ProviderIDs
	}
	if req.Purpose != "" {
		existingConsent.Purpose = req.Purpose
	}
	if req.Type != "" {
		existingConsent.Type = consent.ConsentType(req.Type)
	}
	if req.EndDate != "" {
		endDate, err := time.Parse(time.RFC3339, req.EndDate)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format. Use RFC3339 format (e.g., 2023-12-31T23:59:59Z)"})
			return
		}
		existingConsent.EndDate = endDate
	}
	if req.Status != "" {
		existingConsent.Status = consent.ConsentStatus(req.Status)
	}

	// Update the consent in the service
	if err := h.consentService.Update(ctx, existingConsent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, existingConsent)
}

// RevokeConsent handles revoking a specific consent by its ID
func (h *Handler) RevokeConsent(c *gin.Context) {
	ctx := c.Request.Context()
	consentID := c.Param("id")

	// Validate consent ID
	if consentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "consent ID is required"})
		return
	}

	// Fetch the existing consent
	existingConsent, err := h.consentService.Get(ctx, consentID)
	if err != nil {
		if errors.Is(err, ErrConsentNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Consent not found"})
		} else if errors.Is(err, ErrInvalidConsent) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid consent"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Set the consent status to REVOKED
	existingConsent.Status = consent.ConsentStatusRevoked

	// Update the consent in the service
	if err := h.consentService.Update(ctx, existingConsent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, existingConsent)
}

// Care Coordinator Handlers

type CreateCarePlanRequest struct {
	PatientID     string    `json:"patient_id" binding:"required"`
	Title         string    `json:"title" binding:"required"`
	Description   string    `json:"description"`
	Goals         []string  `json:"goals"`
	Interventions []string  `json:"interventions"`
	Status        string    `json:"status"`
	StartDate     time.Time `json:"start_date"`
	EndDate       time.Time `json:"end_date"`
}

func (h *Handler) CreateCarePlan(c *gin.Context) {
	var req CreateCarePlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	carePlan := &careplan.CarePlan{
		ID:            uuid.New().String(),
		PatientID:     req.PatientID,
		ProviderID:    c.GetString("user_id"),
		Title:         req.Title,
		Description:   req.Description,
		Goals:         req.Goals,
		Interventions: req.Interventions,
		Status:        req.Status,
		StartDate:     req.StartDate,
		EndDate:       req.EndDate,
	}

	if err := h.carePlanService.Create(c.Request.Context(), carePlan); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, carePlan)
}

func (h *Handler) GetCarePlan(c *gin.Context) {
	id := c.Param("id")
	carePlan, err := h.carePlanService.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, carePlan)
}

func (h *Handler) ListCarePlans(c *gin.Context) {
	patientID := c.Query("patient_id")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "patient_id query parameter is required"})
		return
	}

	carePlans, err := h.carePlanService.ListAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, carePlans)
}

type UpdateCarePlanRequest struct {
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	Goals         []string  `json:"goals"`
	Interventions []string  `json:"interventions"`
	Status        string    `json:"status"`
	StartDate     time.Time `json:"start_date"`
	EndDate       time.Time `json:"end_date"`
}

func (h *Handler) UpdateCarePlan(c *gin.Context) {
	id := c.Param("id")
	var req UpdateCarePlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existingCarePlan, err := h.carePlanService.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Care plan not found"})
		return
	}

	// Update fields
	if req.Title != "" {
		existingCarePlan.Title = req.Title
	}
	if req.Description != "" {
		existingCarePlan.Description = req.Description
	}
	if len(req.Goals) > 0 {
		existingCarePlan.Goals = req.Goals
	}
	if len(req.Interventions) > 0 {
		existingCarePlan.Interventions = req.Interventions
	}
	if req.Status != "" {
		existingCarePlan.Status = req.Status
	}
	if !req.StartDate.IsZero() {
		existingCarePlan.StartDate = req.StartDate
	}
	if !req.EndDate.IsZero() {
		existingCarePlan.EndDate = req.EndDate
	}

	if err := h.carePlanService.Update(c.Request.Context(), existingCarePlan); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, existingCarePlan)
}

func (h *Handler) DeleteCarePlan(c *gin.Context) {
	carePlanID := c.Param("id")
	if carePlanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Care Plan ID is required"})
		return
	}

	ctx := c.Request.Context()
	err := h.carePlanService.Delete(ctx, carePlanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete care plan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Care plan deleted successfully"})
}

// RefreshToken handles token refresh for authenticated users
func (h *Handler) RefreshToken(c *gin.Context) {
	// Get the Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token is required"})
		return
	}

	// Extract the token from the header (assuming "Bearer <token>" format)
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
		return
	}

	// Call the auth service to refresh the token
	newToken, err := h.authService.RefreshToken(c.Request.Context(), tokenString)
	if err != nil {
		log.Printf("Token refresh failed: %v", err)
		if errors.Is(err, ErrTokenExpired) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
		} else if errors.Is(err, ErrInvalidToken) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token"})
		}
		return
	}

	// Return the new token
	c.JSON(http.StatusOK, gin.H{"token": newToken})
}

// ChangePassword handles changing the user's password
func (h *Handler) ChangePassword(c *gin.Context) {
	// Define a request struct for password change
	type ChangePasswordRequest struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get the current user's ID from the context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Convert userID to the appropriate type (assuming it's a string or uuid)
	uid, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
		return
	}

	// Use the auth service to change the password
	err := h.authService.ChangePassword(c.Request.Context(), uid, req.CurrentPassword, req.NewPassword)
	if err != nil {
		// Handle different types of errors
		if errors.Is(err, ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to change password"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// EnableMFA handles enabling multi-factor authentication for the current user
func (h *Handler) EnableMFA(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Convert userID to string
	uid, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
		return
	}

	// Call the auth service to enable MFA
	secret, err := h.authService.EnableMFA(c.Request.Context(), uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable MFA", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MFA enabled successfully",
		"secret":  secret,
	})
}

// DisableMFA handles disabling multi-factor authentication for the current user
func (h *Handler) DisableMFA(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Convert userID to string
	uid, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
		return
	}

	// Call the auth service to disable MFA
	err := h.authService.DisableMFA(c.Request.Context(), uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable MFA", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MFA disabled successfully",
	})
}

// Health Check Handler
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"version": "1.0.0",
	})
}

// Audit Log Handlers

func (h *Handler) GetAuditLogs(c *gin.Context) {
	ctx := c.Request.Context()

	// Parse query parameters for filtering and pagination
	from := c.DefaultQuery("from", "0")
	size := c.DefaultQuery("size", "10")

	fromInt, err := strconv.Atoi(from)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'from' parameter"})
		return
	}

	sizeInt, err := strconv.Atoi(size)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'size' parameter"})
		return
	}

	// Collect optional filter parameters
	filters := map[string]interface{}{}
	if userID := c.Query("user_id"); userID != "" {
		filters["user_id"] = userID
	}
	if eventType := c.Query("event_type"); eventType != "" {
		filters["event_type"] = eventType
	}
	if resource := c.Query("resource"); resource != "" {
		filters["resource"] = resource
	}

	// Query audit events
	events, err := h.auditService.QueryEvents(ctx, filters, fromInt, sizeInt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit logs"})
		return
	}

	c.JSON(http.StatusOK, events)
}

func (h *Handler) GetAuditLog(c *gin.Context) {
	ctx := c.Request.Context()

	// Get the specific audit log ID from the URL
	logID := c.Param("id")
	if logID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Audit log ID is required"})
		return
	}

	// Query for a specific audit log (implementation depends on your QueryEvents method)
	filters := map[string]interface{}{
		"request_id": logID,
	}

	events, err := h.auditService.QueryEvents(ctx, filters, 0, 1)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit log"})
		return
	}

	if len(events) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Audit log not found"})
		return
	}

	c.JSON(http.StatusOK, events[0])
}

// Dashboard Handlers

type DashboardStats struct {
	TotalPatients   int `json:"total_patients"`
	TotalProviders  int `json:"total_providers"`
	ActiveCarePlans int `json:"active_care_plans"`
	PendingConsents int `json:"pending_consents"`
}

// GetDashboardStats returns overall statistics for the dashboard
func (h *Handler) GetDashboardStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Get counts from various services
	patients, err := h.patientService.Search(ctx, map[string]interface{}{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get patient count"})
		return
	}

	providers, err := h.providerService.Search(ctx, map[string]interface{}{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get provider count"})
		return
	}

	carePlans, err := h.carePlanService.ListAll(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get care plan count"})
		return
	}

	// Calculate metrics
	metrics := []ComplianceMetric{}

	// 1. Patient Consent Coverage
	activePatients := 0
	patientsWithConsent := make(map[string]bool)
	for _, p := range patients {
		if p.Status == "ACTIVE" {
			activePatients++
		}
	}
	for _, c := range carePlans {
		if c.Status == "active" {
			patientsWithConsent[c.PatientID] = true
		}
	}
	consentScore := float64(len(patientsWithConsent)) / float64(activePatients) * 100
	metrics = append(metrics, ComplianceMetric{
		Category: "Patient Consent Coverage",
		Score:    consentScore,
		Status:   getStatusFromScore(consentScore),
		Details:  fmt.Sprintf("%d of %d active patients have valid consents", len(patientsWithConsent), activePatients),
	})

	// 2. Care Plan Compliance
	activePlans := 0
	upToDatePlans := 0
	for _, cp := range carePlans {
		if cp.Status == "active" {
			activePlans++
			if time.Now().Before(cp.EndDate) {
				upToDatePlans++
			}
		}
	}
	carePlanScore := float64(upToDatePlans) / float64(activePlans) * 100
	metrics = append(metrics, ComplianceMetric{
		Category: "Care Plan Compliance",
		Score:    carePlanScore,
		Status:   getStatusFromScore(carePlanScore),
		Details:  fmt.Sprintf("%d of %d active care plans are up to date", upToDatePlans, activePlans),
	})

	// Calculate overall compliance score (average of all metrics)
	var overallScore float64
	for _, m := range metrics {
		overallScore += m.Score
	}
	overallScore = overallScore / float64(len(metrics))

	// Get pending consents
	pendingConsents := 0
	consents, err := h.consentService.GetByPatient(ctx, "") // Empty patient ID to get all consents
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get pending consents"})
		return
	}
	for _, consent := range consents {
		if consent.Status == "PENDING" {
			pendingConsents++
		}
	}

	stats := DashboardStats{
		TotalPatients:   len(patients),
		TotalProviders:  len(providers),
		ActiveCarePlans: activePlans,
		PendingConsents: pendingConsents,
	}

	c.JSON(http.StatusOK, gin.H{
		"data": stats,
		"message": "Successfully retrieved dashboard statistics",
	})
}

type Activity struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	UserID      string    `json:"user_id"`
	UserType    string    `json:"user_type"`
}

// GetRecentActivities returns recent activities from the audit log
func (h *Handler) GetRecentActivities(c *gin.Context) {
	ctx := c.Request.Context()

	// Get the 10 most recent audit logs
	filters := map[string]interface{}{
		"limit": 10,
		"sort":  "-timestamp",
	}

	auditLogs, err := h.auditService.QueryEvents(ctx, filters, 0, 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve recent activities"})
		return
	}

	// Convert audit logs to activities
	activities := make([]Activity, 0, len(auditLogs))
	for _, log := range auditLogs {
		var details map[string]interface{}
		var userType string
		if err := json.Unmarshal(log.Details, &details); err != nil {
			userType = "unknown"
		} else if userTypeVal, exists := details["userType"]; exists {
			userType = fmt.Sprintf("%v", userTypeVal)
		} else {
			userType = "unknown"
		}

		activity := Activity{
			Type:        string(log.EventType), // Explicitly convert EventType to string
			Description: fmt.Sprintf("%s %s %s", log.Action, log.Resource, log.ResourceID),
			Timestamp:   log.Timestamp,
			UserID:      log.UserID,
			UserType:    userType,
		}
		activities = append(activities, activity)
	}

	c.JSON(http.StatusOK, activities)
}

type ComplianceMetric struct {
	Category string  `json:"category"`
	Score    float64 `json:"score"`
	Status   string  `json:"status"`
	Details  string  `json:"details"`
}

type ComplianceMetrics struct {
	OverallScore float64            `json:"overall_score"`
	Metrics      []ComplianceMetric `json:"metrics"`
}

// GetComplianceMetrics returns compliance metrics for the dashboard
func (h *Handler) GetComplianceMetrics(c *gin.Context) {
	ctx := c.Request.Context()

	// Get all required data
	patients, err := h.patientService.Search(ctx, map[string]interface{}{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get patients"})
		return
	}

	consents, err := h.consentService.GetByPatient(ctx, "") // Empty patient ID to get all consents
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get consents"})
		return
	}

	carePlans, err := h.carePlanService.ListAll(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get care plans"})
		return
	}

	// Calculate metrics
	metrics := []ComplianceMetric{}

	// 1. Patient Consent Coverage
	activePatients := 0
	patientsWithConsent := make(map[string]bool)
	for _, p := range patients {
		if p.Status == "ACTIVE" {
			activePatients++
		}
	}
	for _, c := range consents {
		if c.Status == "ACTIVE" {
			patientsWithConsent[c.PatientID] = true
		}
	}
	consentScore := float64(len(patientsWithConsent)) / float64(activePatients) * 100
	metrics = append(metrics, ComplianceMetric{
		Category: "Patient Consent Coverage",
		Score:    consentScore,
		Status:   getStatusFromScore(consentScore),
		Details:  fmt.Sprintf("%d of %d active patients have valid consents", len(patientsWithConsent), activePatients),
	})

	// 2. Care Plan Compliance
	activePlans := 0
	upToDatePlans := 0
	for _, cp := range carePlans {
		if cp.Status == "active" {
			activePlans++
			if time.Now().Before(cp.EndDate) {
				upToDatePlans++
			}
		}
	}
	carePlanScore := float64(upToDatePlans) / float64(activePlans) * 100
	metrics = append(metrics, ComplianceMetric{
		Category: "Care Plan Compliance",
		Score:    carePlanScore,
		Status:   getStatusFromScore(carePlanScore),
		Details:  fmt.Sprintf("%d of %d active care plans are up to date", upToDatePlans, activePlans),
	})

	// Calculate overall compliance score (average of all metrics)
	var overallScore float64
	for _, m := range metrics {
		overallScore += m.Score
	}
	overallScore = overallScore / float64(len(metrics))

	response := ComplianceMetrics{
		OverallScore: overallScore,
		Metrics:      metrics,
	}

	c.JSON(http.StatusOK, response)
}

// Helper function to determine status based on score
func getStatusFromScore(score float64) string {
	switch {
	case score >= 90:
		return "good"
	case score >= 70:
		return "warning"
	default:
		return "critical"
	}
}

func (h *Handler) LoginWithUsername(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := h.authService.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, ErrMFATokenRequired) {
			c.JSON(http.StatusOK, gin.H{
				"message": "MFA required",
				"token":   token,
				"mfa":     true,
			})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"mfa":   false,
	})
}

func (h *Handler) GetProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	user, err := h.authService.GetUserByID(c.Request.Context(), userID.(string))
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":        user.ID,
		"username":  user.Username,
		"email":     user.Email,
		"roles":     user.Roles,
		"mfa":       user.MFAEnabled,
		"created":   user.CreatedAt,
		"updated":   user.UpdatedAt,
	})
}
