package hunter

import (
	"html/template"
	"io"
	"log"

	"github.com/zricethezav/gitleaks/v7/scan"
)

// DefaultTemplate is the base template used to
// format a Finding into the custom output format
const DefaultTemplate = `{{ with . -}}
{{ range .Leaks -}}Line: {{.LineNumber}}
File: {{ .File }}
Offender: {{ .Offender }}

{{end}}
{{- end}}`

// RenderTemplate renders a Hound finding in a
// custom go template format to the provided writer
func RenderTemplate(w io.Writer, tpl string, f scan.Report) {
	t := template.New("custom")
	t, err := t.Parse(tpl)
	if err != nil {
		log.Fatal("failed to parse template, ", err.Error())
	}

	if err := t.Execute(w, f); err != nil {
		log.Fatal("Failed to use custom template, ", err.Error())
	}
}
