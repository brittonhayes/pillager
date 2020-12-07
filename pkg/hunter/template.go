package hunter

import (
	"html/template"
	"io"
	"log"
)

// DefaultTemplate is the base template used to
// format a Finding into the custom output format
const DefaultTemplate = `{{ range . -}}
{{ if (ge .Count 1) -}}PATH: {{.Path}}
COUNT: {{.Count}}
{{ range .Loot -}}Loot: {{.}}
{{end}}
{{end}}
{{- end}}`

// RenderTemplate renders a Hound finding in a
// custom go template format to the provided writer
func RenderTemplate(w io.Writer, tpl string, f []Finding) {
	t := template.New("custom")
	t, err := t.Parse(tpl)
	if err != nil {
		log.Fatal("failed to parse template, ", err.Error())
	}

	if err := t.Execute(w, f); err != nil {
		log.Fatal("Failed to use custom template, ", err.Error())
	}
}
