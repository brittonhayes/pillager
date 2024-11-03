package report

import (
	"io"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/internal/templates"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Reporter is the interface that each of the canonical output formats implement.
type Reporter interface {
	Report(io.Writer, []pillager.Finding) error
}

// StringToReporter takes in a string representation of the preferred
// reporter.
func StringToReporter(s string) Reporter {
	switch strings.ToLower(s) {
	case "json":
		return JSON{}
	case "raw":
		return Raw{}
	case "yaml":
		return YAML{}
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

// Render renders a finding in a custom go template format to the provided writer.
func Render(w io.Writer, tpl string, findings []pillager.Finding) error {
	t := template.New("custom")
	if tpl == "" {
		log.Debug().Msg("using default template")
		tpl = templates.DefaultTemplate
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
