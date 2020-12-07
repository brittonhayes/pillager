package hunter

import (
	"encoding/json"
	"fmt"
	"github.com/ghodss/yaml"
	"log"
	"os"
)

var _ HuntingDog = Hound{}

// The HuntingDog interface defines the available methods
// for instances of the Hound type
type HuntingDog interface {
	Howl(f []Finding)
}

// A Hound performs the file inspection and returns the results
type Hound struct {
	Config   *Config
	Findings []Finding `json:"findings"`
}

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
	if len(c.Patterns) <= 0 || c.Patterns == nil {
		log.Fatal("Missing regex patterns in Hunter Config")
	}

	return &Hound{c, []Finding{}}
}

// Howl prints out the Findings from the Hound in the preferred output format
func (h Hound) Howl(f []Finding) {
	switch h.Config.Format {
	case JSONFormat:
		b, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			log.Fatal("Failed to unmarshal findings")
		}
		fmt.Println(string(b))
	case YAMLFormat:
		b, err := yaml.Marshal(f)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			return
		}
		fmt.Println(string(b))
	case CustomFormat:
		RenderTemplate(os.Stderr, DefaultTemplate, f)
	}
}
