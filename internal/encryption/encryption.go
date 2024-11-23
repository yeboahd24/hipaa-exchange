package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/spf13/viper"
)

var (
	currentKey []byte
	keyMutex   sync.RWMutex
	lastRotation time.Time
)

type Service interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(ciphertext string) ([]byte, error)
	RotateKey() error
}

type service struct {
	gcm cipher.AEAD
}

func NewService() (Service, error) {
	if err := initializeKey(); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(currentKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &service{gcm: gcm}, nil
}

func (s *service) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	keyMutex.RLock()
	ciphertext := s.gcm.Seal(nonce, nonce, plaintext, nil)
	keyMutex.RUnlock()

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *service) Decrypt(encodedCiphertext string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < s.gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:s.gcm.NonceSize()]
	ciphertext = ciphertext[s.gcm.NonceSize():]

	keyMutex.RLock()
	plaintext, err := s.gcm.Open(nil, nonce, ciphertext, nil)
	keyMutex.RUnlock()

	return plaintext, err
}

func (s *service) RotateKey() error {
	keyMutex.Lock()
	defer keyMutex.Unlock()

	newKey := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return err
	}

	block, err := aes.NewCipher(newKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	currentKey = newKey
	s.gcm = gcm
	lastRotation = time.Now()

	return nil
}

func initializeKey() error {
	keyMutex.Lock()
	defer keyMutex.Unlock()

	if currentKey == nil {
		key := make([]byte, 32) // AES-256
		
		// Try to use the environment variable first
		envKey := os.Getenv("ENCRYPTION_KEY")
		if envKey != "" {
			// Decode hex-encoded key
			decodedKey, err := hex.DecodeString(envKey)
			if err != nil {
				return fmt.Errorf("ENCRYPTION_KEY must be a valid hex string: %v", err)
			}
			if len(decodedKey) != 32 {
				return fmt.Errorf("ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters) long for AES-256")
			}
			key = decodedKey
		} else {
			// If no environment key, generate a random key
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				return err
			}
		}
		
		currentKey = key
		lastRotation = time.Now()
	}

	return nil
}

func StartKeyRotation() {
	rotationPeriod := viper.GetDuration("security.encryption.key_rotation_period")
	if rotationPeriod == 0 {
		rotationPeriod = 90 * 24 * time.Hour // 90 days default
	}

	go func() {
		ticker := time.NewTicker(rotationPeriod)
		for range ticker.C {
			service, err := NewService()
			if err != nil {
				continue
			}
			_ = service.RotateKey()
		}
	}()
}
