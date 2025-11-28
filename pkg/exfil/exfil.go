package exfil

import (
	"context"
	"time"

	"github.com/brittonhayes/pillager"
)

// Exfiltrator defines the interface for exfiltrating findings to external destinations.
// All exfiltration implementations must satisfy this interface.
//
// WARNING: This interface is designed for AUTHORIZED SECURITY TESTING ONLY.
// Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA) and similar laws.
type Exfiltrator interface {
	// Exfiltrate sends a batch of findings to the configured destination.
	// This is suitable for batch-mode operations where all findings are collected first.
	Exfiltrate(ctx context.Context, findings []pillager.Finding) error

	// ExfiltrateStream sends findings one at a time as they're discovered.
	// This is suitable for real-time streaming operations during active scanning.
	ExfiltrateStream(ctx context.Context, findings <-chan pillager.Finding) error

	// Health checks if the exfiltration channel is available and accessible.
	// Returns an error if the destination cannot be reached or authenticated.
	Health(ctx context.Context) error

	// Close cleanly shuts down the exfiltrator, flushing any pending operations.
	Close() error
}

// Config holds configuration for an exfiltrator instance.
type Config struct {
	// Type specifies the exfiltration channel (s3, http, dns, webhook, etc.)
	Type string

	// Mode specifies how findings are sent (stream, batch, archive)
	Mode Mode

	// Enabled controls whether exfiltration is active
	Enabled bool

	// Encryption configuration for securing findings in transit and at rest
	Encryption EncryptionConfig

	// Metadata configuration for tagging and organizing findings
	Metadata MetadataConfig

	// Retry configuration for handling transient failures
	Retry RetryConfig

	// Filters control which findings are exfiltrated
	Filters FilterConfig

	// Options holds type-specific configuration
	Options map[string]interface{}
}

// Mode defines how findings are exfiltrated.
type Mode string

const (
	// ModeStream sends findings one at a time as they're discovered
	ModeStream Mode = "stream"

	// ModeBatch collects all findings and sends them in a single operation
	ModeBatch Mode = "batch"

	// ModeArchive creates a compressed, encrypted archive of all findings
	ModeArchive Mode = "archive"
)

// EncryptionConfig holds encryption settings for exfiltrated data.
type EncryptionConfig struct {
	// Enabled controls whether encryption is used
	Enabled bool

	// Algorithm specifies the encryption algorithm (AES256, ChaCha20, etc.)
	Algorithm string

	// KeySource specifies where to get the encryption key
	// Formats: "env:VAR_NAME", "file:/path/to/key", "inline:base64data"
	KeySource string

	// Key holds the actual encryption key (populated from KeySource)
	Key []byte
}

// MetadataConfig controls what metadata is attached to exfiltrated findings.
type MetadataConfig struct {
	// IncludeHostname adds the hostname to metadata
	IncludeHostname bool

	// IncludeTimestamp adds timestamps to metadata
	IncludeTimestamp bool

	// IncludeOSInfo adds operating system information
	IncludeOSInfo bool

	// IncludeEngagement adds engagement/operation identifier
	IncludeEngagement bool

	// EngagementID is the identifier for this engagement
	EngagementID string

	// OperatorID identifies the operator/analyst
	OperatorID string

	// CustomTags are user-defined tags to add to metadata
	CustomTags map[string]string
}

// RetryConfig controls retry behavior for failed exfiltration attempts.
type RetryConfig struct {
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int

	// BackoffDuration is the initial backoff duration
	BackoffDuration time.Duration

	// MaxBackoff is the maximum backoff duration
	MaxBackoff time.Duration

	// Timeout is the timeout for each exfiltration attempt
	Timeout time.Duration
}

// FilterConfig controls which findings are exfiltrated.
type FilterConfig struct {
	// IncludeRules is a list of rule IDs to include (empty = include all)
	IncludeRules []string

	// ExcludeRules is a list of rule IDs to exclude
	ExcludeRules []string

	// MinEntropy is the minimum entropy value for a finding to be exfiltrated
	MinEntropy float32

	// MaxFindings is the maximum number of findings to exfiltrate (0 = unlimited)
	MaxFindings int
}

// Metadata holds metadata about exfiltrated findings.
type Metadata struct {
	Hostname     string            `json:"hostname,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	OSInfo       string            `json:"os_info,omitempty"`
	EngagementID string            `json:"engagement_id,omitempty"`
	OperatorID   string            `json:"operator_id,omitempty"`
	Version      string            `json:"version"`
	FindingCount int               `json:"finding_count"`
	CustomTags   map[string]string `json:"custom_tags,omitempty"`
}

// Package holds a collection of findings with metadata for exfiltration.
type Package struct {
	Metadata Metadata            `json:"metadata"`
	Findings []pillager.Finding  `json:"findings"`
}

// Registry holds registered exfiltrator factories.
type Registry struct {
	factories map[string]Factory
}

// Factory creates exfiltrator instances.
type Factory func(config Config) (Exfiltrator, error)

// NewRegistry creates a new exfiltrator registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]Factory),
	}
}

// Register registers an exfiltrator factory for a given type.
func (r *Registry) Register(typ string, factory Factory) {
	r.factories[typ] = factory
}

// Create creates an exfiltrator instance for the given configuration.
func (r *Registry) Create(config Config) (Exfiltrator, error) {
	factory, ok := r.factories[config.Type]
	if !ok {
		return nil, &UnsupportedTypeError{Type: config.Type}
	}
	return factory(config)
}

// UnsupportedTypeError is returned when an unknown exfiltrator type is requested.
type UnsupportedTypeError struct {
	Type string
}

func (e *UnsupportedTypeError) Error() string {
	return "unsupported exfiltrator type: " + e.Type
}

// DefaultRegistry is the global exfiltrator registry.
var DefaultRegistry = NewRegistry()

// Create creates an exfiltrator using the default registry.
func Create(config Config) (Exfiltrator, error) {
	return DefaultRegistry.Create(config)
}

// ShouldExfiltrate determines if a finding should be exfiltrated based on filters.
func ShouldExfiltrate(finding pillager.Finding, filters FilterConfig) bool {
	// Check minimum entropy
	if finding.Entropy < filters.MinEntropy {
		return false
	}

	// Check include rules (if specified)
	if len(filters.IncludeRules) > 0 {
		included := false
		for _, rule := range filters.IncludeRules {
			if matchesRule(finding.Description, rule) {
				included = true
				break
			}
		}
		if !included {
			return false
		}
	}

	// Check exclude rules
	for _, rule := range filters.ExcludeRules {
		if matchesRule(finding.Description, rule) {
			return false
		}
	}

	return true
}

// matchesRule checks if a description matches a rule pattern.
// Supports wildcards: "aws-*" matches "aws-access-key", "aws-secret-key", etc.
func matchesRule(description, pattern string) bool {
	// Simple wildcard matching for now
	if pattern == "*" {
		return true
	}

	// Exact match
	if description == pattern {
		return true
	}

	// Prefix wildcard: "aws-*"
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(description) >= len(prefix) && description[:len(prefix)] == prefix
	}

	return false
}
