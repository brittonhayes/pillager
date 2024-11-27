package scanner

import (
	"github.com/brittonhayes/pillager"
)

// DedupFindings removes duplicate findings based on the secret value.
// It preserves the first occurrence of each unique secret.
func DedupFindings(findings []pillager.Finding) []pillager.Finding {
	if len(findings) <= 1 {
		return findings
	}

	// Preallocate the map with the expected size to avoid resizing
	seen := make(map[string]struct{}, len(findings))
	// Reuse the input slice to avoid allocating new memory
	// Keep track of where we're writing with a separate index
	writeIndex := 0

	for i, finding := range findings {
		if _, exists := seen[finding.Secret]; !exists {
			seen[finding.Secret] = struct{}{}
			// Only copy elements if we need to (writeIndex != current index)
			if writeIndex != i {
				findings[writeIndex] = finding
			}
			writeIndex++
		}
	}

	return findings[:writeIndex]
}
