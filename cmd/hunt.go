/*
Copyright © 2020 Britton Hayes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
// Package cmd contains all the commands available in the cli
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
