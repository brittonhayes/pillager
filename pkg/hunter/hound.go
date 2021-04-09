package hunter

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/brittonhayes/pillager/templates"
	"github.com/ghodss/yaml"
	"github.com/zricethezav/gitleaks/v7/scan"
)

var _ Hounder = &Hound{}

// The Hounder interface defines the available methods
// for instances of the Hound type
type Hounder interface {
	Howl(findings scan.Report)
}

// A Hound performs the file inspection and returns the results
type Hound struct {
	Config   *Config
	Findings scan.Report `json:"findings"`
}

// NewHound creates an instance of the Hound type
func NewHound(c *Config) *Hound {
	if c == nil {
		var config Config
		return &Hound{config.Default(), scan.Report{}}
	}
	if c.System == nil {
		log.Fatal("Missing filesystem in Hunter Config")
	}

	return &Hound{c, scan.Report{}}
}

// Howl prints out the Findings from the Hound in the preferred output format
func (h *Hound) Howl(findings scan.Report) {
	if h.Config.Template != "" {
		h.Config.Format = CustomFormat
	}
	switch h.Config.Format {
	case JSONFormat:
		b, err := json.Marshal(&findings.Leaks)
		if err != nil {
			log.Fatal("Failed to unmarshal findings")
		}
		fmt.Println(string(b))
	case YAMLFormat:
		b, err := yaml.Marshal(&findings.Leaks)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			return
		}
		fmt.Println(string(b))
	case HTMLFormat:
		RenderTemplate(os.Stdout, templates.HTML, findings)
	case HTMLTableFormat:
		RenderTemplate(os.Stdout, templates.HTMLTable, findings)
	case MarkdownFormat:
		RenderTemplate(os.Stdout, templates.Markdown, findings)
	case TableFormat:
		RenderTemplate(os.Stdout, templates.Table, findings)
	case CustomFormat:
		RenderTemplate(os.Stdout, h.Config.Template, findings)
	default:
		RenderTemplate(os.Stdout, templates.Simple, findings)
	}
}
