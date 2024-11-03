package pillager

// Finding contains information about strings that
// have been captured by a tree-sitter query.
type Finding struct {
	Description string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Match string

	// Secret contains the full content of what is matched in
	// the tree-sitter query.
	Secret string

	// File is the name of the file containing the finding
	File string

	// Entropy is the shannon entropy of Value
	Entropy float32

	// Rule is the name of the rule that was matched
	RuleID string
}

// Options holds configuration for scanners
type Options struct {
	Path      string    `toml:"path"`
	Template  string    `toml:"template"`
	Workers   int       `toml:"workers"`
	Verbose   bool      `toml:"verbose"`
	Redact    bool      `toml:"redact"`
	Reporter  string    `toml:"reporter"`
	Rules     []Rule    `toml:"rules"`
	Allowlist Allowlist `toml:"allowlist"`
}

// Rule represents a scanning rule
type Rule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Path        string   `toml:"path"`
	Regex       string   `toml:"regex"`
	Keywords    []string `toml:"keywords"`
	Tags        []string `toml:"tags"`
	Allowlist   Allowlist
}

// Allowlist represents paths and patterns to ignore
type Allowlist struct {
	Paths   []string `toml:"paths"`
	Regexes []string `toml:"regexes"`
}
