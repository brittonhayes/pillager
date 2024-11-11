package report

import (
	"encoding/json"
	"io"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/internal/templates"
)

type JSON struct{}

func (JSON) Report(w io.Writer, findings []pillager.Finding) error {
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(&findings); err != nil {
		return err
	}

	return nil
}

type JSONPretty struct{}

func (JSONPretty) Report(w io.Writer, findings []pillager.Finding) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(&findings); err != nil {
		return err
	}

	return nil
}

type HTML struct{}

func (HTML) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, templates.HTML, findings)
}

type Markdown struct{}

func (Markdown) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, templates.Markdown, findings)
}

type Table struct{}

func (Table) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, templates.Table, findings)
}

type Wordlist struct{}

func (Wordlist) Report(w io.Writer, findings []pillager.Finding) error {
	return Render(w, templates.Wordlist, findings)
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
