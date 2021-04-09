package rules

import (
	"log"

	"github.com/BurntSushi/toml"
	gitleaks "github.com/zricethezav/gitleaks/v7/config"
)

// Load loads the config file into an array of gitleaks rules
func Load(filepath string) gitleaks.Config {
	var (
		config gitleaks.TomlLoader
		err    error
	)

	if filepath != "" {
		_, err = toml.DecodeFile(filepath, &config)
	} else {
		_, err = toml.Decode(DefaultConfig, &config)
	}
	if err != nil {
		log.Fatal("Failed to read in config ", err.Error())
	}

	c, err := config.Parse()
	if err != nil {
		log.Fatal("Failed to parse in toml config")
	}

	return c
}
