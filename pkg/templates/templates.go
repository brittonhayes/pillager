// Package templates contains a compilation of go templates for rendering secret findings.
package templates

import (
	_ "embed"
	"io"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/report"
)

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

// DefaultTemplate is the base template used to format a Finding into the
// custom output format.
const DefaultTemplate = `{{ with . -}}
{{ range . -}}
Line: 	{{ quote .StartLine}}
File: 	{{ quote .File }}
Secret: {{ quote .Secret }}
---
{{ end -}}{{- end}}`

// Render renders a finding in a custom go template format to the provided writer.
func Render(w io.Writer, tpl string, findings []report.Finding) error {
	t := template.New("custom")
	if tpl == "" {
		log.Debug().Msg("using default template")
		tpl = DefaultTemplate
	}

	t, err := t.Funcs(sprig.TxtFuncMap()).Parse(tpl)
	if err != nil {
		return errors.Wrap(err, "failed to parse template")
	}

	if err := t.Execute(w, findings); err != nil {
		return errors.Wrap(err, "Failed to use custom template")
	}

	return nil
}
