/*
Copyright © 2020 Britton Hayes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// Package pillager is a tool for hunting through filesystems for sensitive information.
//
// # Installation
//
// Go
//
//	go install github.com/brittonhayes/pillager@latest
//
// Windows
//
//	scoop bucket add pillager https://github.com/brittonhayes/pillager-scoop.git
//	scoop install pillager
//
// OSX/Linux
//
//	brew tap brittonhayes/homebrew-pillager
//	brew install pillager
//
//go:generate golangci-lint run ./...
package pillager

// Finding contains information about strings that
// have been captured by a scanner query.
type Finding struct {
	Description string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	// Match is the full content of what is matched by the scanner.
	Match string

	// Secret contains the full content of what is matched in
	// the scanner query.
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
