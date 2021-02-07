package validate

import (
	"log"
	"os"

	"github.com/spf13/afero"
)

var _ Validator = &Validation{}

type Validation struct{}

// New creates a new validation
func New() *Validation {
	return &Validation{}
}

type Validator interface {
	Path(fs afero.Fs, path string) string
}

// Path checks if a filepath exists and
// returns it if so, otherwise returns a default path
func (v *Validation) Path(fs afero.Fs, path string) string {
	ok, err := afero.Exists(fs, path)
	if err != nil {
		log.Printf("ERROR: %s", err.Error())
		os.Exit(1)
	}

	if ok {
		return path
	}

	log.Fatal("no valid path provided")
	return "."
}
