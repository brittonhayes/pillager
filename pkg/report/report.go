package report

import (
	"io"
	"strings"
	"text/template"

	"encoding/json"

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
	case "json-pretty":
		return JSONPretty{}
	case "wordlist":
		return Wordlist{}
	case "table":
		return Table{}
	case "html":
		return HTML{}
	case "markdown":
		return Markdown{}
	case "custom":
		return Custom{}
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

	funcMap := sprig.TxtFuncMap()
	funcMap["json"] = func(v interface{}) string {
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		// Escape quotes and backslashes for HTML attributes
		escaped := strings.ReplaceAll(string(b), `"`, `&quot;`)
		escaped = strings.ReplaceAll(escaped, `\`, `\\`)
		return escaped
	}

	t, err := t.Funcs(funcMap).Parse(tpl)
	if err != nil {
		return errors.Wrap(err, "failed to parse template")
	}

	if err := t.Execute(w, findings); err != nil {
		return errors.Wrap(err, "Failed to use custom template")
	}

	return nil
}
