package hunter

import (
	reg "github.com/mingrammer/commonregex"
	"github.com/spf13/afero"
	"regexp"
)

// Config takes all of the configurable
// parameters for a Hunter
type Config struct {
	System   afero.Fs
	Patterns []*regexp.Regexp
	BasePath string
}

// Default loads the default configuration
// for the Hunter
func (h *Config) Default() *Config {
	fs := afero.NewOsFs()
	return &Config{
		System: fs,
		Patterns: []*regexp.Regexp{
			reg.CreditCardRegex,
			reg.BtcAddressRegex,
			reg.VISACreditCardRegex,
			reg.GitRepoRegex,
		},
		BasePath: CheckPath(fs, "."),
	}
}
