package format

import "strings"

const (
	StyleJSON Style = iota
	StyleYAML
	StyleTable
	StyleHTML
	StyleHTMLTable
	StyleMarkdown
	StyleCustom
)

type Style int

func (s Style) String() string {
	return [...]string{"json", "yaml", "table", "html", "html-table", "markdown", "custom"}[s]
}

// StringToFormat takes in a string representation of the preferred
// output format and returns to enum equivalent
func StringToFormat(s string) Style {
	switch strings.ToLower(s) {
	case "yaml":
		return StyleYAML
	case "table":
		return StyleTable
	case "html":
		return StyleHTML
	case "html-table":
		return StyleHTMLTable
	case "markdown":
		return StyleMarkdown
	case "custom":
		return StyleCustom
	default:
		return StyleJSON
	}
}
