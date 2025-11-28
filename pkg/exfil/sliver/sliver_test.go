package sliver

import (
	"testing"

	"github.com/brittonhayes/pillager"
)

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

