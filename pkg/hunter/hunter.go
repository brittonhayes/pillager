package hunter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/format"
	"github.com/brittonhayes/pillager/templates"
	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"
	"gopkg.in/yaml.v2"
)

// Hunter is the secret scanner.
type Hunter struct {
	*pillager.Config
}

// New creates an instance of the Hunter.
func New(opts ...pillager.ConfigOption) (*Hunter, error) {
	return &Hunter{
		Config: pillager.NewConfig(opts...),
	}, nil
}

// Hunt walks over the filesystem at the configured path, looking for sensitive information.
func (h *Hunter) Hunt() (scan.Report, error) {
	opt := options.Options{Path: h.ScanPath, Verbose: h.Verbose, Threads: h.Workers}
	conf := config.Config{Allowlist: h.Gitleaks.Allowlist, Rules: h.Gitleaks.Rules}

	scanner := scan.NewNoGitScanner(opt, conf)
	log.Debug().Str("style", h.Style.String()).Bool("verbose", h.Verbose).Msg("scanner created")

	report, err := scanner.Scan()
	if err != nil {
		return scan.Report{}, err
	}

	return report, nil
}

// Report prints out the Findings in the preferred output format.
func (h *Hunter) Report(w io.Writer, results scan.Report) error {
	switch h.Style {
	case format.StyleJSON:
		encoder := json.NewEncoder(w)
		err := encoder.Encode(&results.Leaks)
		if err != nil {
			return err
		}

	case format.StyleYAML:
		b, err := yaml.Marshal(&results.Leaks)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\n", string(b))

	case format.StyleHTML:
		return format.RenderTemplate(w, templates.HTML, results)

	case format.StyleHTMLTable:
		return format.RenderTemplate(w, templates.HTMLTable, results)

	case format.StyleMarkdown:
		return format.RenderTemplate(w, templates.Markdown, results)

	case format.StyleTable:
		return format.RenderTemplate(w, templates.Table, results)

	case format.StyleCustom:
		return format.RenderTemplate(w, h.Template, results)

	default:
		return format.RenderTemplate(w, templates.Simple, results)
	}

	return nil
}
