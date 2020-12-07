// Package cmd contains the command line logic
//
// The cmd package is the primary consumer of all packages in the /pkg directory
package cmd

import (
	"fmt"
	reg "github.com/mingrammer/commonregex"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"pillager/pkg/hunter"
	"regexp"
)

var (
	financial  bool
	github     bool
	telephone  bool
	email      bool
	address    bool
	monochrome bool
	verbose    bool
	output     string
)

// huntCmd represents the hunt command
var huntCmd = &cobra.Command{
	Use:   "hunt",
	Short: "Hunt for loot",
	Long:  "Hunt inside the file system for valuable information",
	Args:  cobra.MinimumNArgs(1),
	RunE:  StartHunt(),
}

func init() {
	rootCmd.AddCommand(huntCmd)
	huntCmd.Flags().BoolVarP(&financial, "financial", "f", false, "filter for financial information")
	huntCmd.Flags().BoolVarP(&github, "github", "g", false, "filter for github information")
	huntCmd.Flags().BoolVarP(&telephone, "telephone", "t", false, "filter for telephone information")
	huntCmd.Flags().BoolVarP(&email, "email", "e", false, "filter for email information")
	huntCmd.Flags().BoolVarP(&address, "address", "a", false, "filter for address information")
	huntCmd.Flags().BoolVarP(&monochrome, "monochrome", "m", false, "toggle colorful output")
	huntCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "toggle verbose output")
	huntCmd.Flags().StringVarP(&output, "output", "o", "yaml", "set output format (json, yaml)")
}

func StartHunt() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		fs := afero.NewOsFs()
		c := hunter.Config{
			System:     fs,
			Patterns:   setPattern(),
			BasePath:   hunter.CheckPath(fs, args[0]),
			Monochrome: monochrome,
			Verbose:    verbose,
			Format:     hunter.StringToFormat(output),
		}
		h := hunter.NewHunter(&c)
		err := h.Hunt()
		if err != nil {
			return err
		}
		return nil
	}
}

// setPattern sets the patterns to hunt for based on provided filters
func setPattern() []*regexp.Regexp {
	defaultPattern := []*regexp.Regexp{
		reg.CreditCardRegex,
		reg.SSNRegex,
		reg.BtcAddressRegex,
		reg.GitRepoRegex,
		reg.PhonesWithExtsRegex,
		reg.EmailRegex,
	}

	if financial {
		fmt.Println("FILTER:\tFinancial")
		filtered := append([]*regexp.Regexp{}, reg.BtcAddressRegex, reg.CreditCardRegex)
		return filtered
	}

	if github {
		fmt.Println("FILTER:\tGithub")
		filtered := append([]*regexp.Regexp{}, reg.GitRepoRegex)
		return filtered
	}

	if telephone {
		fmt.Println("FILTER:\tTelephone")
		filtered := append([]*regexp.Regexp{}, reg.PhonesWithExtsRegex)
		return filtered
	}

	if email {
		fmt.Println("FILTER:\tEmail")
		filtered := append([]*regexp.Regexp{}, reg.EmailRegex)
		return filtered
	}

	if address {
		fmt.Println("FILTER:\tAddress")
		filtered := append([]*regexp.Regexp{}, reg.StreetAddressRegex)
		return filtered
	}

	return defaultPattern
}
