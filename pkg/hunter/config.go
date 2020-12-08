package hunter

import (
	"github.com/BurntSushi/toml"
	"github.com/brittonhayes/pillager/pkg/config"
	reg "github.com/mingrammer/commonregex"
	"github.com/spf13/afero"
	gitleaks "github.com/zricethezav/gitleaks/v7/config"
	"log"
	"regexp"
)

var DefaultPatterns = []*regexp.Regexp{
	reg.EmailRegex,
	reg.GitRepoRegex,
}

// Config takes all of the configurable
// parameters for a Hunter
type Config struct {
	System   afero.Fs
	BasePath string
	Verbose  bool
	Rules    []gitleaks.Rule
	Format   Format
}

// Default loads the default configuration
// for the Hunter
func (c *Config) Default() *Config {
	fs := afero.NewOsFs()
	return &Config{
		System:   fs,
		BasePath: CheckPath(fs, "."),
		Verbose:  false,
		Rules:    LoadRules(""),
		Format:   JSONFormat,
	}
}

func LoadRules(filepath string) []gitleaks.Rule {
	var gl gitleaks.TomlLoader
	var err error
	if filepath != "" {
		_, err = toml.DecodeFile(filepath, &gl)
	} else {
		_, err = toml.Decode(config.DefaultConfig, &gl)
	}
	if err != nil {
		log.Fatal("Failed to read in config ", err.Error())
	}

	c, err := gl.Parse()
	if err != nil {
		log.Fatal("Failed to parse in toml config")
	}

	return c.Rules
}
