package format

import (
	"html/template"
	"io"

	"github.com/pkg/errors"
	"github.com/zricethezav/gitleaks/v7/scan"
)

// DefaultTemplate is the base template used to
// format a Finding into the custom output format.
const DefaultTemplate = `{{ with . -}}
{{ range .Leaks -}}
Line: {{.LineNumber}}
File: {{ .File }}
Offender: {{ .Offender }}

{{ end -}}{{- end}}`

// RenderTemplate renders a finding in a
// custom go template format to the provided writer.
func RenderTemplate(w io.Writer, tpl string, f scan.Report) error {
	t := template.New("custom")
	t, err := t.Parse(tpl)
	if err != nil {
		return errors.Wrap(err, "failed to parse template")
	}

	if err := t.Execute(w, f); err != nil {
		return errors.Wrap(err, "Failed to use custom template")
	}

	return nil
}
