// Package templates contains a compilation of go templates for rendering secret findings.
package templates

import (
	_ "embed"
)

var (
	//go:embed wordlist.tmpl
	Wordlist string

	//go:embed html.tmpl
	HTML string

	//go:embed markdown.tmpl
	Markdown string
)

// DefaultTemplate is the base template used to format a Finding into the
// custom output format.
const DefaultTemplate = `{{ with . -}}
{{ range . -}}
Line: 	{{ quote .StartLine}}
File: 	{{ quote .File }}
Secret: {{ quote .Secret }}
---
{{ end -}}{{- end}}`
