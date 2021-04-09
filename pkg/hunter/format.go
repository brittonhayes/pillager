package hunter

import "strings"

const (
	JSONFormat Format = iota + 1
	YAMLFormat
	TableFormat
	HTMLFormat
	HTMLTableFormat
	MarkdownFormat
	CustomFormat
)

type Format int

func (f Format) String() string {
	return [...]string{"json", "yaml", "table", "html", "html-table", "markdown", "custom"}[f]
}

// StringToFormat takes in a string representation of the preferred
// output format and returns to enum equivalent
func StringToFormat(s string) Format {
	switch strings.ToLower(s) {
	case "yaml":
		return YAMLFormat
	case "table":
		return TableFormat
	case "html":
		return HTMLFormat
	case "html-table":
		return HTMLTableFormat
	case "markdown":
		return MarkdownFormat
	case "custom":
		return CustomFormat
	default:
		return JSONFormat
	}
}
