package sliver

import (
	"regexp"
	"strings"

	"github.com/brittonhayes/pillager"
)

// Credential represents a parsed credential for Sliver's credential store.
type Credential struct {
	Username   string
	Plaintext  string
	Hash       string
	HashType   string
	IsCracked  bool
	Collection string // Type of credential (e.g., "AWS", "GitHub", "SSH Key")
}

// ExtractCredentials parses findings and extracts structured credentials.
func ExtractCredentials(findings []pillager.Finding) []Credential {
	var credentials []Credential

	for _, finding := range findings {
		creds := parseFindings(finding)
		credentials = append(credentials, creds...)
	}

	return credentials
}

func parseFindings(finding pillager.Finding) []Credential {
	var credentials []Credential

	switch {
	case strings.Contains(finding.RuleID, "aws") || containsTag(finding.Tags, "aws"):
		creds := parseAWSCredentials(finding)
		credentials = append(credentials, creds...)

	case strings.Contains(finding.RuleID, "github") || containsTag(finding.Tags, "github"):
		cred := parseGitHubToken(finding)
		if cred != nil {
			credentials = append(credentials, *cred)
		}

	case strings.Contains(finding.RuleID, "private-key") || strings.Contains(finding.RuleID, "ssh"):
		cred := parseSSHKey(finding)
		if cred != nil {
			credentials = append(credentials, *cred)
		}

	case strings.Contains(finding.RuleID, "password") || containsTag(finding.Tags, "password"):
		cred := parsePassword(finding)
		if cred != nil {
			credentials = append(credentials, *cred)
		}

	case strings.Contains(finding.RuleID, "api") || strings.Contains(finding.RuleID, "token"):
		cred := parseAPIToken(finding)
		if cred != nil {
			credentials = append(credentials, *cred)
		}

	case strings.Contains(finding.RuleID, "database") || strings.Contains(finding.RuleID, "db"):
		cred := parseDatabaseCredential(finding)
		if cred != nil {
			credentials = append(credentials, *cred)
		}
	}

	return credentials
}

func parseAWSCredentials(finding pillager.Finding) []Credential {
	var credentials []Credential

	if strings.Contains(finding.RuleID, "access-key") || strings.Contains(finding.Description, "Access Key") {
		credentials = append(credentials, Credential{
			Username:   "AWS_ACCESS_KEY_ID",
			Plaintext:  finding.Secret,
			Collection: "AWS",
			IsCracked:  true,
		})
	}

	if strings.Contains(finding.RuleID, "secret-key") || strings.Contains(finding.Description, "Secret Key") {
		credentials = append(credentials, Credential{
			Username:   "AWS_SECRET_ACCESS_KEY",
			Plaintext:  finding.Secret,
			Collection: "AWS",
			IsCracked:  true,
		})
	}

	return credentials
}

func parseGitHubToken(finding pillager.Finding) *Credential {
	tokenType := "GitHub PAT"
	secret := finding.Secret
	switch {
	case strings.HasPrefix(secret, "ghp_"):
		tokenType = "GitHub Personal Access Token"
	case strings.HasPrefix(secret, "gho_"):
		tokenType = "GitHub OAuth Token"
	case strings.HasPrefix(secret, "ghs_"):
		tokenType = "GitHub Server-to-Server Token"
	case strings.HasPrefix(secret, "ghr_"):
		tokenType = "GitHub Refresh Token"
	}

	return &Credential{
		Username:   tokenType,
		Plaintext:  secret,
		Collection: "GitHub",
		IsCracked:  true,
	}
}

func parseSSHKey(finding pillager.Finding) *Credential {
	keyType := "SSH Private Key"
	secret := finding.Secret
	switch {
	case strings.Contains(secret, "RSA PRIVATE KEY"):
		keyType = "SSH RSA Private Key"
	case strings.Contains(secret, "EC PRIVATE KEY"):
		keyType = "SSH EC Private Key"
	case strings.Contains(secret, "OPENSSH PRIVATE KEY"):
		keyType = "SSH OpenSSH Private Key"
	case strings.Contains(secret, "DSA PRIVATE KEY"):
		keyType = "SSH DSA Private Key"
	}

	return &Credential{
		Username:   keyType,
		Plaintext:  secret,
		Collection: "SSH",
		IsCracked:  true,
	}
}

func parsePassword(finding pillager.Finding) *Credential {
	username := extractUsernameFromContext(finding)
	if username == "" {
		username = "unknown"
	}

	return &Credential{
		Username:   username,
		Plaintext:  finding.Secret,
		Collection: "Password",
		IsCracked:  true,
	}
}

func parseAPIToken(finding pillager.Finding) *Credential {
	apiType := "API Token"
	id := strings.ToLower(finding.RuleID)
	desc := strings.ToLower(finding.Description)

	switch {
	case strings.Contains(id, "slack") || strings.Contains(desc, "slack"):
		apiType = "Slack API Token"
	case strings.Contains(id, "stripe") || strings.Contains(desc, "stripe"):
		apiType = "Stripe API Key"
	case strings.Contains(id, "twilio") || strings.Contains(desc, "twilio"):
		apiType = "Twilio API Key"
	case strings.Contains(id, "sendgrid") || strings.Contains(desc, "sendgrid"):
		apiType = "SendGrid API Key"
	case strings.Contains(id, "mailgun") || strings.Contains(desc, "mailgun"):
		apiType = "Mailgun API Key"
	case strings.Contains(id, "heroku") || strings.Contains(desc, "heroku"):
		apiType = "Heroku API Key"
	}

	return &Credential{
		Username:   apiType,
		Plaintext:  finding.Secret,
		Collection: "API",
		IsCracked:  true,
	}
}

func parseDatabaseCredential(finding pillager.Finding) *Credential {
	dbType := "Database Credential"
	id := strings.ToLower(finding.RuleID)
	desc := strings.ToLower(finding.Description)

	switch {
	case strings.Contains(id, "postgres") || strings.Contains(desc, "postgres"):
		dbType = "PostgreSQL"
	case strings.Contains(id, "mysql") || strings.Contains(desc, "mysql"):
		dbType = "MySQL"
	case strings.Contains(id, "mongodb") || strings.Contains(desc, "mongodb"):
		dbType = "MongoDB"
	case strings.Contains(id, "redis") || strings.Contains(desc, "redis"):
		dbType = "Redis"
	case strings.Contains(id, "mssql") || strings.Contains(desc, "mssql"):
		dbType = "MSSQL"
	}

	username := extractUsernameFromConnectionString(finding.Secret)
	if username == "" {
		username = "connection_string"
	}

	return &Credential{
		Username:   username,
		Plaintext:  finding.Secret,
		Collection: dbType,
		IsCracked:  true,
	}
}

func extractUsernameFromContext(finding pillager.Finding) string {
	patterns := []string{
		`user[name]*[=:]\s*['"]*([a-zA-Z0-9_.-]+)`,
		`login[=:]\s*['"]*([a-zA-Z0-9_.-]+)`,
		`account[=:]\s*['"]*([a-zA-Z0-9_.-]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(finding.Match); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

func extractUsernameFromConnectionString(connStr string) string {
	re := regexp.MustCompile(`://([^:@]+)[:@]`)
	if matches := re.FindStringSubmatch(connStr); len(matches) > 1 {
		return matches[1]
	}

	re = regexp.MustCompile(`user[name]*=([^;& ]+)`)
	if matches := re.FindStringSubmatch(connStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func containsTag(tags []string, tag string) bool {
	tagLower := strings.ToLower(tag)
	for _, t := range tags {
		if strings.ToLower(t) == tagLower {
			return true
		}
	}
	return false
}
