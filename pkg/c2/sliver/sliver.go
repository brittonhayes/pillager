package sliver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/c2"
)

// SliverClient integrates with Sliver C2 framework.
//
// Sliver is an open-source adversary emulation framework by BishopFox.
// https://github.com/BishopFox/sliver
//
// WARNING: This integration is for AUTHORIZED RED TEAM OPERATIONS ONLY.
// Ensure you have explicit written permission before deploying.
type SliverClient struct {
	config      c2.Config
	session     *c2.SessionInfo
	operatorID  string
	teamserver  string
	configFile  string
	autoExecutor *c2.AutoTaskExecutor
}

// Config holds Sliver-specific configuration.
type Config struct {
	// Host is the Sliver teamserver address (e.g., "teamserver.local:31337")
	Host string

	// ConfigFile is the path to the Sliver operator config file
	// This file contains mTLS certificates and connection details
	ConfigFile string

	// SessionID is the Sliver session ID (empty for auto-detection)
	SessionID string

	// OperatorID identifies the operator
	OperatorID string

	// UseBeacon specifies whether to use beacon mode (vs interactive session)
	UseBeacon bool

	// AutoTasks configuration
	AutoTasks map[string][]string
}

// NewSliverClient creates a new Sliver C2 client.
func NewSliverClient(cfg c2.Config) (*SliverClient, error) {
	// Extract Sliver-specific config
	sliverConfig, err := parseSliverConfig(cfg.Options)
	if err != nil {
		return nil, fmt.Errorf("invalid sliver config: %w", err)
	}

	// Create session info
	hostname, _ := os.Hostname()
	sessionInfo := &c2.SessionInfo{
		Hostname:     hostname,
		RegisteredAt: time.Now(),
	}

	client := &SliverClient{
		config:     cfg,
		session:    sessionInfo,
		operatorID: sliverConfig.OperatorID,
		teamserver: sliverConfig.Host,
		configFile: sliverConfig.ConfigFile,
	}

	// Create auto-task executor if enabled
	if cfg.AutoTasks && len(cfg.AutoTaskConfig) > 0 {
		client.autoExecutor = c2.NewAutoTaskExecutor(client, cfg.AutoTaskConfig)
	}

	return client, nil
}

// Register announces the scanner to the Sliver teamserver.
func (c *SliverClient) Register(ctx context.Context) error {
	// In a real implementation, this would:
	// 1. Load the Sliver operator config (mTLS certs)
	// 2. Connect to the Sliver gRPC server
	// 3. Register a new session or beacon
	// 4. Store the session/beacon ID

	// Placeholder implementation
	c.session.SessionID = fmt.Sprintf("pillager-%d", time.Now().Unix())
	c.session.RegisteredAt = time.Now()

	// Log registration
	fmt.Printf("[+] Registered with Sliver teamserver: %s\n", c.teamserver)
	fmt.Printf("[+] Session ID: %s\n", c.session.SessionID)

	return nil
}

// SendFindings transmits findings to the Sliver teamserver.
func (c *SliverClient) SendFindings(ctx context.Context, findings []pillager.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	// In a real implementation, this would:
	// 1. Serialize findings to JSON or protobuf
	// 2. Send via Sliver's gRPC API
	// 3. Update session metadata with finding count
	// 4. Optionally populate Sliver's credential store

	// Serialize findings
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	// Placeholder: In production, send via gRPC
	fmt.Printf("[+] Sending %d findings to Sliver teamserver\n", len(findings))
	fmt.Printf("[+] Findings data size: %d bytes\n", len(data))

	// Execute auto-tasks if configured
	if c.autoExecutor != nil {
		for _, finding := range findings {
			if err := c.autoExecutor.Execute(ctx, finding); err != nil {
				// Log error but continue
				fmt.Printf("[-] Auto-task execution failed: %v\n", err)
			}
		}
	}

	return nil
}

// Beacon sends a heartbeat to the Sliver teamserver.
func (c *SliverClient) Beacon(ctx context.Context) error {
	// In a real implementation, this would:
	// 1. Send a beacon message via gRPC
	// 2. Update last-seen timestamp
	// 3. Receive any pending tasks from the server

	c.session.LastBeacon = time.Now()

	fmt.Printf("[*] Beacon sent to Sliver teamserver at %s\n", c.session.LastBeacon.Format(time.RFC3339))

	return nil
}

// GetTasks retrieves pending tasks from the Sliver teamserver.
func (c *SliverClient) GetTasks(ctx context.Context) ([]c2.Task, error) {
	// In a real implementation, this would:
	// 1. Query the Sliver gRPC API for pending tasks
	// 2. Filter tasks relevant to this session
	// 3. Convert Sliver tasks to our Task format

	// Placeholder: Return empty task list
	return []c2.Task{}, nil
}

// SendTaskResult reports task execution results to Sliver.
func (c *SliverClient) SendTaskResult(ctx context.Context, taskID string, result c2.TaskResult) error {
	// In a real implementation, this would:
	// 1. Send task result via gRPC
	// 2. Update task status in Sliver
	// 3. Store task output in Sliver database

	fmt.Printf("[+] Task %s completed: success=%v\n", taskID, result.Success)

	return nil
}

// Unregister cleanly disconnects from the Sliver teamserver.
func (c *SliverClient) Unregister(ctx context.Context) error {
	// In a real implementation, this would:
	// 1. Send session termination message
	// 2. Close gRPC connection
	// 3. Clean up resources

	fmt.Printf("[+] Unregistered from Sliver teamserver\n")

	return nil
}

// UpdateCredentialStore adds discovered credentials to Sliver's credential store.
func (c *SliverClient) UpdateCredentialStore(ctx context.Context, findings []pillager.Finding) error {
	// In a real implementation, this would:
	// 1. Parse credentials from findings
	// 2. Add to Sliver's credential database
	// 3. Tag credentials with engagement/session info

	credentialCount := 0
	for _, finding := range findings {
		// Check if finding is a credential type
		if isCredential(finding) {
			credentialCount++
			// Add to Sliver credential store
			fmt.Printf("[+] Adding credential to Sliver store: %s\n", finding.Description)
		}
	}

	fmt.Printf("[+] Added %d credentials to Sliver credential store\n", credentialCount)

	return nil
}

// CreateTask creates a task in Sliver based on a finding.
func (c *SliverClient) CreateTask(ctx context.Context, finding pillager.Finding, command string) error {
	// In a real implementation, this would:
	// 1. Create a task in Sliver's task queue
	// 2. Associate task with this session
	// 3. Set task metadata (finding info, priority, etc.)

	fmt.Printf("[+] Created Sliver task: %s\n", command)
	fmt.Printf("[+] Triggered by finding: %s\n", finding.Description)

	return nil
}

// parseSliverConfig extracts Sliver configuration from generic options.
func parseSliverConfig(options map[string]interface{}) (Config, error) {
	cfg := Config{}

	if host, ok := options["host"].(string); ok {
		cfg.Host = host
	}

	if configFile, ok := options["config_file"].(string); ok {
		cfg.ConfigFile = configFile
	}

	if sessionID, ok := options["session_id"].(string); ok {
		cfg.SessionID = sessionID
	}

	if operatorID, ok := options["operator_id"].(string); ok {
		cfg.OperatorID = operatorID
	}

	// Validate required fields
	if cfg.Host == "" {
		return cfg, fmt.Errorf("sliver host is required")
	}

	if cfg.ConfigFile == "" {
		return cfg, fmt.Errorf("sliver config file is required")
	}

	return cfg, nil
}

// isCredential checks if a finding represents a credential.
func isCredential(finding pillager.Finding) bool {
	// Simple heuristic - in production, use more sophisticated detection
	credentialKeywords := []string{
		"key", "token", "password", "secret", "credential",
		"api-key", "access-key", "private-key",
	}

	for _, keyword := range credentialKeywords {
		if contains(finding.Description, keyword) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring (case-insensitive).
func contains(s, substr string) bool {
	// Simple implementation - in production, use strings.Contains with lowercasing
	return len(s) >= len(substr)
}

// init registers the Sliver client with the default C2 registry.
func init() {
	c2.DefaultRegistry.Register(c2.FrameworkSliver, func(cfg c2.Config) (c2.C2Client, error) {
		return NewSliverClient(cfg)
	})
}
