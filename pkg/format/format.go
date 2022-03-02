// Package format contains the renderer and available output formats
package format

import (
	"strings"
)

// StringToReporter takes in a string representation of the preferred
// reporter.
func StringToReporter(s string) Reporter {
	switch strings.ToLower(s) {
	case "json":
		return JSON{}
	case "yaml":
		return YAML{}
	case "toml":
		return TOML{}
	case "table":
		return Table{}
	case "html":
		return HTML{}
	case "html-table":
		return HTMLTable{}
	case "markdown":
		return Markdown{}
	case "custom":
		return Custom{}
	case "simple":
		return Simple{}
	default:
		return JSON{}
	}
}
