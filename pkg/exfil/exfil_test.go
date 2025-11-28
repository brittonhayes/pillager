package exfil

import (
	"context"
	"encoding/base64"
	"os"
	"testing"

	"github.com/brittonhayes/pillager"
)

func TestCreatePackage(t *testing.T) {
	findings := []pillager.Finding{
		{
			Description: "AWS Access Key",
			Secret:      "AKIAIOSFODNN7EXAMPLE",
			File:        "/test/file.txt",
			StartLine:   10,
			EndLine:     10,
		},
	}

	pkg := CreatePackage(findings)

	if pkg.Metadata.FindingCount != 1 {
		t.Errorf("expected FindingCount=1, got %d", pkg.Metadata.FindingCount)
	}

	if len(pkg.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(pkg.Findings))
	}

	if pkg.Metadata.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", pkg.Metadata.Version)
	}
}

func TestLoadEncryptionKey_Env(t *testing.T) {
	// Test environment variable
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	os.Setenv("TEST_EXFIL_KEY", encoded)
	defer os.Unsetenv("TEST_EXFIL_KEY")

	loaded, err := LoadEncryptionKey("env:TEST_EXFIL_KEY")
	if err != nil {
		t.Fatalf("LoadEncryptionKey failed: %v", err)
	}

	if len(loaded) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(loaded))
	}
}

func TestLoadEncryptionKey_Empty(t *testing.T) {
	loaded, err := LoadEncryptionKey("")
	if err != nil {
		t.Fatalf("LoadEncryptionKey failed: %v", err)
	}

	if loaded != nil {
		t.Errorf("expected nil for empty key source, got %v", loaded)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate 32-byte key for AES-256
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("This is a secret message with findings!")

	// Encrypt
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Compare
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Invalid size for AES-256
	plaintext := []byte("test")

	_, err := Encrypt(plaintext, key)
	if err == nil {
		t.Error("expected error for invalid key size, got nil")
	}
}

func TestSerializeFindings(t *testing.T) {
	findings := []pillager.Finding{
		{
			Description: "GitHub Token",
			Secret:      "ghp_1234567890abcdefghijklmnopqrstuvwx",
			File:        "/test/config.yml",
			StartLine:   5,
			EndLine:     5,
		},
	}

	data, err := SerializeFindings(findings)
	if err != nil {
		t.Fatalf("SerializeFindings failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty serialized data")
	}

	// Check that it's valid JSON
	if data[0] != '{' {
		t.Error("expected JSON object")
	}
}

// MockExfiltrator for testing
type MockExfiltrator struct {
	exfiltratedFindings []pillager.Finding
	closed              bool
}

func (m *MockExfiltrator) Exfiltrate(ctx context.Context, findings []pillager.Finding) error {
	m.exfiltratedFindings = findings
	return nil
}

func (m *MockExfiltrator) Close() error {
	m.closed = true
	return nil
}

func TestRegistry(t *testing.T) {
	// Register mock exfiltrator
	Register("mock", func(cfg Config) (Exfiltrator, error) {
		return &MockExfiltrator{}, nil
	})

	// Create mock exfiltrator
	cfg := Config{
		Type: "mock",
	}

	exfiltrator, err := Create(cfg)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	mock, ok := exfiltrator.(*MockExfiltrator)
	if !ok {
		t.Fatal("exfiltrator is not a MockExfiltrator")
	}

	// Test exfiltration
	findings := []pillager.Finding{
		{Description: "test", Secret: "secret"},
	}

	err = mock.Exfiltrate(context.Background(), findings)
	if err != nil {
		t.Fatalf("Exfiltrate failed: %v", err)
	}

	if len(mock.exfiltratedFindings) != 1 {
		t.Errorf("expected 1 exfiltrated finding, got %d", len(mock.exfiltratedFindings))
	}

	// Test close
	err = mock.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !mock.closed {
		t.Error("exfiltrator was not closed")
	}
}

func TestCreate_UnsupportedType(t *testing.T) {
	cfg := Config{
		Type: "unsupported-type",
	}

	_, err := Create(cfg)
	if err == nil {
		t.Error("expected error for unsupported type, got nil")
	}
}
