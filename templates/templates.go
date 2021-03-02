package templates

import _ "embed"

var (
	//go:embed simple.tmpl
	Simple string

	//go:embed html.tmpl
	HTML string

	//go:embed markdown.tmpl
	Markdown string

	//go:embed table.tmpl
	Table string

	//go:embed html-table.tmpl
	HTMLTable string
)
