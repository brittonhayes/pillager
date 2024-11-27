package report

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"

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

type CSV struct{}

func (CSV) Report(w io.Writer, findings []pillager.Finding) error {
	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()

	// Write header
	header := []string{
		"Description",
		"Secret",
		"File",
		"StartLine",
		"EndLine",
		"StartColumn",
		"EndColumn",
		"Match",
	}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write findings
	for _, f := range findings {
		record := []string{
			f.Description,
			f.Secret,
			f.File,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			f.Match,
		}
		if err := csvWriter.Write(record); err != nil {
			return err
		}
	}

	return nil
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
