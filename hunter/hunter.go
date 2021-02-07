package hunter

import (
	"fmt"
	"os"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"
)

// Hunter holds the required fields to implement
// the Hunting interface and utilize the hunter package
type Hunter struct {
	Config *Config
	Hound  *Hound
}

var _ Hunting = Hunter{}

// Hunting is the primary API interface for the hunter package
type Hunting interface {
	Hunt() error
}

// NewHunter creates an instance of the Hunter type
func NewHunter(c *Config) *Hunter {
	if c == nil {
		var conf Config
		return &Hunter{conf.Default(), NewHound(conf.Default())}
	}

	err := c.Validate()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	return &Hunter{c, NewHound(c)}
}

// Hunt walks over the filesystem at the configured path, looking for sensitive information
func (h Hunter) Hunt() error {
	h.Hound = NewHound(h.Config)
	if _, err := os.Stat(h.Config.BasePath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist")
	}

	opt := options.Options{Path: h.Config.BasePath, Verbose: h.Config.Verbose, Threads: h.Config.Workers}
	conf := config.Config{Allowlist: h.Config.Gitleaks.Allowlist, Rules: h.Config.Gitleaks.Rules}

	scanner := scan.NewNoGitScanner(opt, conf)
	report, err := scanner.Scan()
	if err != nil {
		return err
	}

	if !opt.Verbose {
		h.Hound.Howl(report)
	}

	return nil
}
