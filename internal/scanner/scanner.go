package scanner

import (
	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/report"
)

// Scanner defines the interface for secret scanning implementations
type Scanner interface {
	// Scan performs the secret scanning operation on the given path
	Scan(path string) ([]pillager.Finding, error)

	// Reporter returns the reporter for the scanner
	Reporter() report.Reporter

	// ScanPath returns the path that the scanner is scanning
	ScanPath() string
}
