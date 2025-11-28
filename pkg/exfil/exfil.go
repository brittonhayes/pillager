package exfil

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/brittonhayes/pillager"
)

// Exfiltrator defines the interface for exfiltrating findings to external destinations.
type Exfiltrator interface {
	Exfiltrate(ctx context.Context, findings []pillager.Finding) error
	Close() error
}

// Config holds configuration for an exfiltrator instance.
type Config struct {
	Type          string
	EncryptionKey string
	Compress      bool
	S3            *S3Options
	Webhook       *WebhookOptions
	Sliver        *SliverOptions
}

// S3Options holds S3-specific exfiltration configuration.
type S3Options struct {
	Bucket    string
	Region    *string
	Endpoint  *string
	Prefix    *string
	AccessKey *string
	SecretKey *string
}

// WebhookOptions holds webhook-specific exfiltration configuration.
type WebhookOptions struct {
	URL     string
	Headers map[string]string
	Timeout *time.Duration
}

// SliverOptions holds Sliver C2-specific exfiltration configuration.
type SliverOptions struct {
	ConfigPath       string
	SessionID        *string
	LootName         *string
	LootType         *string
	ParseCredentials *bool
}

// Metadata holds metadata about exfiltrated findings.
type Metadata struct {
	Hostname     string    `json:"hostname,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	Version      string    `json:"version"`
	FindingCount int       `json:"finding_count"`
}

// Package holds findings with metadata for exfiltration.
type Package struct {
	Metadata Metadata           `json:"metadata"`
	Findings []pillager.Finding `json:"findings"`
}

// Registry holds registered exfiltrator factories.
var registry = make(map[string]Factory)

// Factory creates exfiltrator instances.
type Factory func(config Config) (Exfiltrator, error)

// Register registers an exfiltrator factory for a given type.
func Register(typ string, factory Factory) {
	registry[typ] = factory
}

// Create creates an exfiltrator instance for the given configuration.
func Create(config Config) (Exfiltrator, error) {
	factory, ok := registry[config.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported exfiltrator type: %s", config.Type)
	}
	return factory(config)
}

// CreatePackage creates a package with metadata for exfiltration.
func CreatePackage(findings []pillager.Finding) Package {
	hostname, _ := os.Hostname()
	return Package{
		Metadata: Metadata{
			Hostname:     hostname,
			Timestamp:    time.Now(),
			Version:      "2.0.0",
			FindingCount: len(findings),
		},
		Findings: findings,
	}
}

// LoadEncryptionKey loads an encryption key from various sources.
func LoadEncryptionKey(keySource string) ([]byte, error) {
	if keySource == "" {
		return nil, nil
	}

	// Environment variable: env:VAR_NAME
	if strings.HasPrefix(keySource, "env:") {
		varName := strings.TrimPrefix(keySource, "env:")
		value := os.Getenv(varName)
		if value == "" {
			return nil, fmt.Errorf("environment variable %s not set", varName)
		}
		return base64.StdEncoding.DecodeString(value)
	}

	// File: file:/path/to/key
	if strings.HasPrefix(keySource, "file:") {
		path := strings.TrimPrefix(keySource, "file:")
		return os.ReadFile(path)
	}

	// Direct base64 key
	return base64.StdEncoding.DecodeString(keySource)
}

// Encrypt encrypts data using AES-256-GCM.
func Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using AES-256-GCM.
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SerializeFindings serializes findings to JSON.
func SerializeFindings(findings []pillager.Finding) ([]byte, error) {
	pkg := CreatePackage(findings)
	return json.MarshalIndent(pkg, "", "  ")
}
