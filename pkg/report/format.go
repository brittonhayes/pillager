package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/internal/templates"
	"gopkg.in/yaml.v2"
)

type JSON struct{}

func (j JSON) Report(w io.Writer, findings []pillager.Finding) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(&findings); err != nil {
		return err
	}

	return nil
}

type Raw struct{}

func (r Raw) Report(w io.Writer, findings []pillager.Finding) error {
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(&findings); err != nil {
		return err
	}

	return nil
}

type YAML struct{}

func (y YAML) Report(w io.Writer, findings []pillager.Finding) error {
	b, err := yaml.Marshal(&findings)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s\n", string(b))

	return nil
}

type HTML struct{}

func (h HTML) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, templates.HTML, findings)
}

type HTMLTable struct{}

func (h HTMLTable) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, templates.HTMLTable, findings)
}

type Markdown struct{}

func (m Markdown) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, templates.Markdown, findings)
}

type Table struct{}

func (t Table) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, templates.Table, findings)
}

type Custom struct {
	template string
}

func (c *Custom) WithTemplate(t string) {
	c.template = t
}

func (c Custom) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, c.template, findings)
}

type Simple struct{}

func (s Simple) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, templates.DefaultTemplate, findings)
}
