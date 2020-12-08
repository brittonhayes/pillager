package hunter

//go:generate pie Findings.Filter

import (
	"encoding/json"
	"fmt"
	"github.com/ghodss/yaml"
	"log"
	"os"
)

var _ Retriever = &Hound{}

// The Retriever interface defines the available methods
// for instances of the Hound type
type Retriever interface {
	FilterEmpty() *Hound
	Fetch()
}

// A Hound performs the file inspection and returns the results
type Hound struct {
	Config   *Config
	Findings Findings `json:"findings"`
}

// Findings contains a slice of Finding
type Findings []Finding

// Finding houses the details of a hound's hunt
type Finding struct {
	Count   int      `json:"count,omitempty"`
	Message string   `json:"message,omitempty"`
	Path    string   `json:"path,omitempty"`
	Loot    []string `json:"loot,omitempty"`
}

// NewHound creates an instance of the Hound type
func NewHound(c *Config) *Hound {
	if c == nil {
		var config Config
		return &Hound{config.Default(), []Finding{}}
	}
	if c.System == nil {
		log.Fatal("Missing filesystem in Hunter Config")
	}

	return &Hound{c, []Finding{}}
}

// Fetch prints out the Findings from the Hound in the preferred output format
func (h Hound) Fetch() {
	switch h.Config.Format {
	case JSONFormat:
		b, err := json.Marshal(&h.Findings)
		if err != nil {
			log.Fatal("Failed to unmarshal findings")
		}
		fmt.Println(string(b))
	case YAMLFormat:
		b, err := yaml.Marshal(&h.Findings)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			return
		}
		fmt.Println(string(b))
	case CustomFormat:
		RenderTemplate(os.Stdout, DefaultTemplate, h.Findings)
	}
}

func (h *Hound) FilterEmpty() *Hound {
	h.Findings.Filter(func(f Finding) bool {
		return len(f.Loot) > 0
	}).Filter(func(f Finding) bool {
		return f.Path != ""
	})
	return h
}
