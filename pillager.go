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
	ScanPath  string
	Template  string
	Workers   int
	Verbose   bool
	Redact    bool
	Reporter  string
	Rules     []Rule
	Allowlist Allowlist
}

// Rule represents a scanning rule
type Rule struct {
	ID          string
	Description string
	Path        string
	Regex       string
	Keywords    []string
	Tags        []string
	Allowlist   Allowlist
}

// Allowlist represents paths and patterns to ignore
type Allowlist struct {
	Paths   []string
	Regexes []string
	Commits []string
}
