package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/mesikahq/hipaa-exchange/internal/audit"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidToken       = errors.New("invalid token")
	ErrMFARequired        = errors.New("multi-factor authentication required")
	ErrInvalidMFACode     = errors.New("invalid MFA code")
)

type Claims struct {
	jwt.RegisteredClaims
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	MFAValid bool     `json:"mfa_valid"`
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Roles        []string  `json:"roles"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	MFASecret    string    `json:"-"`
	LastLogin    time.Time `json:"last_login"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Status       string    `json:"status"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
}

type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	User         *User  `json:"user"`
	RequiresMFA  bool   `json:"requires_mfa"`
}

type Service interface {
	Register(ctx context.Context, username, email, password string, roles []string) (*User, error)
	Login(ctx context.Context, username, password string) (string, error)
	LoginWithEmail(ctx context.Context, email, password string) (*LoginResponse, error)
	ValidateToken(ctx context.Context, tokenString string) (*Claims, error)
	RefreshToken(ctx context.Context, tokenString string) (string, error)
	EnableMFA(ctx context.Context, userID string) (string, error)
	ValidateMFA(ctx context.Context, userID, code string) error
	ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error
	DeactivateUser(ctx context.Context, userID string) error
	Initialize(ctx context.Context) error
	ListUsers(ctx context.Context) ([]User, error)
	UpdateUser(ctx context.Context, userID, username string, roles []string) error
	UpdateUserProfile(ctx context.Context, userID, firstName, lastName, email string) (*User, error)
	DisableMFA(ctx context.Context, userID string) error
	GetUserByID(ctx context.Context, userID string) (*User, error)
}

type service struct {
	db           *pgxpool.Pool
	audit        audit.Service
	jwtSecret    []byte
	tokenExpiry  time.Duration
	refreshLimit time.Duration
}

type AuthServiceConfig struct {
	JWTSecret    string
	TokenExpiry  time.Duration
	RefreshLimit time.Duration
}

func NewService(db *pgxpool.Pool, audit audit.Service, config AuthServiceConfig) Service {
	return &service{
		db:           db,
		audit:        audit,
		jwtSecret:    []byte(config.JWTSecret),
		tokenExpiry:  config.TokenExpiry,
		refreshLimit: config.RefreshLimit,
	}
}

// Initialize creates the necessary database tables
func (s *service) Initialize(ctx context.Context) error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		roles TEXT[] NOT NULL DEFAULT '{}',
		mfa_enabled BOOLEAN NOT NULL DEFAULT false,
		mfa_secret VARCHAR(255),
		last_login TIMESTAMP WITH TIME ZONE,
		created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
		status VARCHAR(50) NOT NULL DEFAULT 'active',
		first_name VARCHAR(255),
		last_name VARCHAR(255)
	);
	CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);
	`
	_, err := s.db.Exec(ctx, createTableSQL)
	return err
}

func (s *service) Register(ctx context.Context, username, email, password string, roles []string) (*User, error) {
	log.Printf("Registering user %s with email %s and roles %v", username, email, roles)
	log.Printf("Registration password length: %d", len(password))
	log.Printf("Registration password bytes: %v", []byte(password))

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	log.Printf("Generated password hash: %s", string(hashedPassword))
	log.Printf("Generated hash length: %d", len(hashedPassword))

	// Verify the hash immediately
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		log.Printf("WARNING: Password verification failed immediately after hashing: %v", err)
		return nil, fmt.Errorf("password verification failed: %w", err)
	}
	log.Printf("Initial password verification successful during registration")

	user := &User{
		ID:           uuid.New().String(),
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		Roles:        roles,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
		Status:       "active",
	}

	_, err = s.db.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash, roles, created_at, updated_at, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		user.ID, user.Username, user.Email, user.PasswordHash, user.Roles,
		user.CreatedAt, user.UpdatedAt, user.Status)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	details, _ := json.Marshal(map[string]interface{}{
		"username": username,
		"email":    email,
		"roles":    roles,
	})
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      user.ID,
		Action:      "REGISTER",
		Resource:    "user",
		ResourceID:  user.ID,
		Status:      "success",
		Sensitivity: "HIGH",
		Details:     json.RawMessage(details),
	})

	log.Printf("Successfully registered user %s with ID %s", username, user.ID)
	return user, nil
}

func (s *service) Login(ctx context.Context, username, password string) (string, error) {
	log.Printf("Attempting login for user: %s", username)
	log.Printf("Input password length: %d", len(password))

	var user User
	var lastLogin sql.NullTime
	var mfaSecret sql.NullString
	err := s.db.QueryRow(ctx,
		`SELECT id, username, email, password_hash, roles, mfa_enabled, mfa_secret, last_login, status, first_name, last_name
		 FROM users WHERE username = $1`,
		username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Roles,
		&user.MFAEnabled, &mfaSecret, &lastLogin, &user.Status, &user.FirstName, &user.LastName)

	if err != nil {
		log.Printf("Login failed for user %s: %v", username, err)
		return "", ErrInvalidCredentials
	}

	log.Printf("Found user %s with hash %s", username, user.PasswordHash)
	log.Printf("User details - ID: %s, MFA Enabled: %v, Status: %s", user.ID, user.MFAEnabled, user.Status)
	log.Printf("User roles: %v", user.Roles)
	log.Printf("Stored password hash length: %d", len(user.PasswordHash))

	// Convert NULL values to empty strings/zero values
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
		log.Printf("MFA Secret found: %s", mfaSecret.String)
	}
	if lastLogin.Valid {
		user.LastLogin = lastLogin.Time
		log.Printf("Last login found: %v", lastLogin.Time)
	}

	if user.Status != "active" {
		log.Printf("User %s status is not active: %s", username, user.Status)
		return "", ErrInvalidCredentials
	}

	// Compare the provided password with the stored hash
	log.Printf("Comparing password hash...")
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		log.Printf("Password mismatch for user %s: %v", username, err)
		log.Printf("Provided password: %s", password)
		log.Printf("Stored hash: %s", user.PasswordHash)
		details, _ := json.Marshal(map[string]interface{}{
			"reason": "invalid_password",
		})
		s.audit.LogEvent(ctx, &audit.AuditEvent{
			EventType:   audit.EventAccess,
			Action:      "login",
			Status:      "failure",
			Sensitivity: "HIGH",
			Details:     json.RawMessage(details),
		})
		return "", ErrInvalidCredentials
	}

	log.Printf("Password verified for user %s", username)
	token, err := s.generateToken(&user)
	if err != nil {
		return "", err
	}

	_, err = s.db.Exec(ctx,
		"UPDATE users SET last_login = $1 WHERE id = $2",
		time.Now().UTC(), user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to update last login: %v", err)
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      user.ID,
		Action:      "LOGIN",
		Resource:    "user",
		ResourceID:  user.ID,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	if user.MFAEnabled {
		return token, ErrMFARequired
	}

	return token, nil
}

func (s *service) LoginWithEmail(ctx context.Context, email, password string) (*LoginResponse, error) {
	log.Printf("Attempting login for email: %s", email)
	log.Printf("Login password length: %d", len(password))
	log.Printf("Login password bytes: %v", []byte(password))

	var user User
	var lastLogin sql.NullTime
	var mfaSecret sql.NullString
	var firstName, lastName sql.NullString
	err := s.db.QueryRow(ctx,
		`SELECT id, username, email, password_hash, roles, mfa_enabled, mfa_secret, last_login, status, first_name, last_name
		 FROM users WHERE email = $1`,
		email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Roles,
		&user.MFAEnabled, &mfaSecret, &lastLogin, &user.Status, &firstName, &lastName)

	if err != nil {
		log.Printf("Login failed for email %s: %v", email, err)
		return nil, ErrInvalidCredentials
	}

	log.Printf("Retrieved user from database:")
	log.Printf("User ID: %s", user.ID)
	log.Printf("Username: %s", user.Username)
	log.Printf("Stored hash length: %d", len(user.PasswordHash))
	log.Printf("Stored password hash bytes: %v", []byte(user.PasswordHash))

	// Convert NULL values to empty strings/zero values
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
	}
	if lastLogin.Valid {
		user.LastLogin = lastLogin.Time
	}
	if firstName.Valid {
		user.FirstName = firstName.String
	}
	if lastName.Valid {
		user.LastName = lastName.String
	}

	if user.Status != "active" {
		log.Printf("User %s status is not active: %s", email, user.Status)
		return nil, ErrInvalidCredentials
	}

	// Compare the provided password with the stored hash
	log.Printf("Attempting to verify password for user %s", email)
	log.Printf("Stored password hash: %s", user.PasswordHash)
	log.Printf("Input password length: %d", len(password))
	log.Printf("Password contains whitespace prefix/suffix: %v", len(strings.TrimSpace(password)) != len(password))
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		log.Printf("Password verification failed for user %s: %v", email, err)
		details, _ := json.Marshal(map[string]interface{}{
			"reason": "invalid_password",
		})
		s.audit.LogEvent(ctx, &audit.AuditEvent{
			EventType:   audit.EventAccess,
			Action:      "login",
			Status:      "failure",
			Sensitivity: "HIGH",
			Details:     json.RawMessage(details),
		})
		return nil, ErrInvalidCredentials
	}

	token, err := s.generateToken(&user)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	_, err = s.db.Exec(ctx,
		"UPDATE users SET last_login = $1 WHERE id = $2",
		time.Now().UTC(), user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update last login: %v", err)
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      user.ID,
		Action:      "LOGIN",
		Resource:    "user",
		ResourceID:  user.ID,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	response := &LoginResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User: &User{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Roles:     user.Roles,
		},
	}

	if user.MFAEnabled {
		response.RequiresMFA = true
	}

	return response, nil
}

func (s *service) generateToken(user *User) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
			Subject:   user.ID,
		},
		UserID:   user.ID,
		Username: user.Username,
		Roles:    user.Roles,
		MFAValid: !user.MFAEnabled,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *service) generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *service) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Check if user is still active
		var user User
		err := s.db.QueryRow(ctx,
			`SELECT id, status
			 FROM users WHERE id = $1`,
			claims.UserID).Scan(
			&user.ID, &user.Status)

		if err != nil {
			return nil, ErrUserNotFound
		}

		if user.Status != "active" {
			return nil, ErrUserNotFound
		}

		if !claims.MFAValid {
			return nil, ErrMFARequired
		}

		return claims, nil
	}

	return nil, ErrInvalidToken
}

func (s *service) RefreshToken(ctx context.Context, tokenString string) (string, error) {
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		return "", err
	}

	// Check if token is within refresh limit
	if time.Until(claims.ExpiresAt.Time) > s.refreshLimit {
		return "", ErrTokenExpired
	}

	newClaims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
		UserID:   claims.UserID,
		Username: claims.Username,
		Roles:    claims.Roles,
		MFAValid: claims.MFAValid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	return token.SignedString(s.jwtSecret)
}

func (s *service) EnableMFA(ctx context.Context, userID string) (string, error) {
	// Generate MFA secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	secretStr := base64.StdEncoding.EncodeToString(secret)

	_, err := s.db.Exec(ctx,
		`UPDATE users SET mfa_enabled = TRUE, mfa_secret = $1 WHERE id = $2`,
		secretStr, userID)

	if err != nil {
		return "", err
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "ENABLE_MFA",
		Resource:    "user",
		ResourceID:  userID,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return secretStr, nil
}

func (s *service) ValidateMFA(ctx context.Context, userID, code string) error {
	var user User
	err := s.db.QueryRow(ctx,
		`SELECT id, mfa_secret
		 FROM users WHERE id = $1`,
		userID).Scan(
		&user.ID, &user.MFASecret)

	if err != nil {
		return ErrUserNotFound
	}

	if len(user.MFASecret) < 6 || code != user.MFASecret[:6] {
		s.audit.LogEvent(ctx, &audit.AuditEvent{
			EventType:   audit.EventAccess,
			UserID:      userID,
			Action:      "VALIDATE_MFA",
			Resource:    "user",
			ResourceID:  userID,
			Status:      "failure",
			Sensitivity: "HIGH",
		})
		return ErrInvalidMFACode
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      userID,
		Action:      "VALIDATE_MFA",
		Resource:    "user",
		ResourceID:  userID,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return nil
}

func (s *service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	var user User
	err := s.db.QueryRow(ctx,
		`SELECT id, password_hash
		 FROM users WHERE id = $1`,
		userID).Scan(
		&user.ID, &user.PasswordHash)

	if err != nil {
		return ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		s.audit.LogEvent(ctx, &audit.AuditEvent{
			EventType:   audit.EventModify,
			UserID:      userID,
			Action:      "CHANGE_PASSWORD",
			Resource:    "user",
			ResourceID:  userID,
			Status:      "failure",
			Sensitivity: "HIGH",
		})
		return ErrInvalidCredentials
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(ctx,
		`UPDATE users SET password_hash = $1 WHERE id = $2`,
		string(hash), userID)

	if err != nil {
		return err
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "CHANGE_PASSWORD",
		Resource:    "user",
		ResourceID:  userID,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return nil
}

func (s *service) DeactivateUser(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE users SET status = 'inactive' WHERE id = $1`,
		userID)

	if err != nil {
		return err
	}

	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "DEACTIVATE",
		Resource:    "user",
		ResourceID:  userID,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return nil
}

func (s *service) ListUsers(ctx context.Context) ([]User, error) {
    query := `
        SELECT id, username, email, roles, mfa_enabled, last_login, created_at, updated_at, status, first_name, last_name
        FROM users
        ORDER BY created_at DESC
    `

    rows, err := s.db.Query(ctx, query)
    if err != nil {
        return nil, fmt.Errorf("failed to query users: %v", err)
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var user User
        err := rows.Scan(
            &user.ID, 
            &user.Username, 
            &user.Email, 
            &user.Roles, 
            &user.MFAEnabled, 
            &user.LastLogin, 
            &user.CreatedAt, 
            &user.UpdatedAt, 
            &user.Status,
            &user.FirstName,
            &user.LastName,
        )
        if err != nil {
            return nil, fmt.Errorf("failed to scan user: %v", err)
        }
        users = append(users, user)
    }

    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("error iterating users: %v", err)
    }

    return users, nil
}

func (s *service) UpdateUser(ctx context.Context, userID, username string, roles []string) error {
    query := `
        UPDATE users 
        SET username = COALESCE(NULLIF($2, ''), username), 
            roles = COALESCE($3, roles), 
            updated_at = NOW() 
        WHERE id = $1
    `

    // Execute the update query
    result, err := s.db.Exec(ctx, query, userID, username, roles)
    if err != nil {
        return fmt.Errorf("failed to update user: %v", err)
    }

    // Check if any rows were affected
    rowsAffected := result.RowsAffected()
    if rowsAffected == 0 {
        return ErrUserNotFound
    }

    // Log the user update for audit purposes
    s.audit.LogEvent(ctx, &audit.AuditEvent{
        EventType:   audit.EventModify,
        UserID:      userID,
        Action:      "UPDATE_USER",
        Resource:    "user",
        ResourceID:  userID,
        Status:      "success",
        Sensitivity: "HIGH",
        Details:     json.RawMessage([]byte(fmt.Sprintf(`{"username_updated": "%s", "roles_updated": %v}`, username, len(roles) > 0))),
    })

    return nil
}

func (s *service) UpdateUserProfile(ctx context.Context, userID, firstName, lastName, email string) (*User, error) {
    query := `
        UPDATE users 
        SET first_name = COALESCE(NULLIF($2, ''), first_name), 
            last_name = COALESCE(NULLIF($3, ''), last_name), 
            email = COALESCE(NULLIF($4, ''), email), 
            updated_at = NOW() 
        WHERE id = $1
    `

    // Execute the update query
    result, err := s.db.Exec(ctx, query, userID, firstName, lastName, email)
    if err != nil {
        return nil, fmt.Errorf("failed to update user profile: %v", err)
    }

    // Check if any rows were affected
    rowsAffected := result.RowsAffected()
    if rowsAffected == 0 {
        return nil, ErrUserNotFound
    }

    // Log the user update for audit purposes
    s.audit.LogEvent(ctx, &audit.AuditEvent{
        EventType:   audit.EventModify,
        UserID:      userID,
        Action:      "UPDATE_USER_PROFILE",
        Resource:    "user",
        ResourceID:  userID,
        Status:      "success",
        Sensitivity: "HIGH",
        Details:     json.RawMessage([]byte(fmt.Sprintf(`{"first_name_updated": "%s", "last_name_updated": "%s", "email_updated": "%s"}`, firstName, lastName, email))),
    })

    // Fetch the updated user
    var user User
    err = s.db.QueryRow(ctx,
        `SELECT id, username, email, roles, mfa_enabled, last_login, created_at, updated_at, status, first_name, last_name
         FROM users WHERE id = $1`,
        userID).Scan(
        &user.ID, 
        &user.Username, 
        &user.Email, 
        &user.Roles, 
        &user.MFAEnabled, 
        &user.LastLogin, 
        &user.CreatedAt, 
        &user.UpdatedAt, 
        &user.Status,
        &user.FirstName,
        &user.LastName,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to fetch updated user: %v", err)
    }

    return &user, nil
}

func (s *service) DisableMFA(ctx context.Context, userID string) error {
	// Disable MFA for the user
	_, err := s.db.Exec(ctx,
		`UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL WHERE id = $1`,
		userID)
	if err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	// Log the MFA disable action
	err = s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "DISABLE_MFA",
		Resource:    "user",
		ResourceID:  userID,
		Status:      "success",
		Sensitivity: "HIGH",
	})
	if err != nil {
		log.Printf("Failed to log MFA disable action: %v", err)
	}

	return nil
}

func (s *service) GetUserByID(ctx context.Context, userID string) (*User, error) {
	var user User
	err := s.db.QueryRow(ctx,
		`SELECT id, username, email, roles, mfa_enabled, last_login, created_at, updated_at, status, first_name, last_name
		 FROM users WHERE id = $1`,
		userID).Scan(
		&user.ID, 
		&user.Username, 
		&user.Email, 
		&user.Roles, 
		&user.MFAEnabled, 
		&user.LastLogin, 
		&user.CreatedAt, 
		&user.UpdatedAt, 
		&user.Status,
		&user.FirstName,
		&user.LastName,
	)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return &user, nil
}
