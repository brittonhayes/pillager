package format

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/brittonhayes/pillager/pkg/templates"
	"github.com/zricethezav/gitleaks/v8/report"
	"gopkg.in/yaml.v2"
)

type Reporter interface {
	Report(io.Writer, []report.Finding) error
}

type JSON struct{}

func (j JSON) Report(w io.Writer, findings []report.Finding) error {
	encoder := json.NewEncoder(w)
	err := encoder.Encode(&findings)
	if err != nil {
		return err
	}

	return nil
}

type YAML struct{}

func (y YAML) Report(w io.Writer, findings []report.Finding) error {
	b, err := yaml.Marshal(&findings)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s\n", string(b))

	return nil
}

type HTML struct{}

func (h HTML) Report(w io.Writer, findings []report.Finding) error {
	return templates.Render(w, templates.HTML, findings)
}

type HTMLTable struct{}

func (h HTMLTable) Report(w io.Writer, findings []report.Finding) error {
	return templates.Render(w, templates.HTMLTable, findings)
}

type Markdown struct{}

func (m Markdown) Report(w io.Writer, findings []report.Finding) error {
	return templates.Render(w, templates.Markdown, findings)
}

type Table struct{}

func (t Table) Report(w io.Writer, findings []report.Finding) error {
	return templates.Render(w, templates.Table, findings)
}

type Custom struct {
	template string
}

func (c *Custom) WithTemplate(t string) {
	c.template = t
}

func (c Custom) Report(w io.Writer, findings []report.Finding) error {
	return templates.Render(w, c.template, findings)
}

type Simple struct{}

func (s Simple) Report(w io.Writer, findings []report.Finding) error {
	return templates.Render(w, templates.Simple, findings)
}
