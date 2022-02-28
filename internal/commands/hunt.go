// Package pillager contains the command line logic
//
// The pillager package is the primary consumer of all packages in the /pkg directory
package pillager

import (
	"os"
	"runtime"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/format"
	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/spf13/cobra"
)

var (
	verbose     bool
	level       string
	rulesConfig string
	style       string
	templ       string
	workers     int
)

// huntCmd represents the hunt command.
var huntCmd = &cobra.Command{
	Use:   "hunt [directory]",
	Short: "Hunt for loot",
	Long:  "Hunt inside the file system for valuable information",
	Example: `
	Basic:
		pillager hunt .
	
	JSON Format:
		pillager hunt ./example -f json
	
	YAML Format:
		pillager hunt . -f yaml
	
	HTML Format:
		pillager hunt . -f html > results.html
	
	HTML Table Format:
		pillager hunt . -f html-table > results.html
	
	Markdown Table Format:
		pillager hunt . -f table > results.md
	
	Custom Go Template Format:
		pillager hunt . --template "{{ range .Leaks}}Leak: {{.Line}}{{end}}"
	
	Custom Go Template Format from Template File:
		pillager hunt ./example --template "$(cat templates/simple.tmpl)"
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		h, err := hunter.New(
			pillager.WithScanPath(args[0]),
			pillager.WithWorkers(workers),
			pillager.WithVerbose(verbose),
			pillager.WithTemplate(templ),
			pillager.WithStyle(format.StringToFormat(style)),
			pillager.WithLogLevel(level),
		)
		if err != nil {
			return err
		}

		results, err := h.Hunt()
		if err != nil {
			return err
		}

		err = h.Report(os.Stdout, results)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(huntCmd)
	huntCmd.Flags().IntVarP(&workers, "workers", "w", runtime.NumCPU(), "number of concurrent workers")
	huntCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable scanner verbose output")
	huntCmd.Flags().StringVarP(&level, "log-level", "l", "error", "set logging level")
	huntCmd.Flags().StringVarP(&rulesConfig, "rules", "r", "", "path to gitleaks rules.toml config")
	huntCmd.Flags().StringVarP(&style, "format", "f", "json", "set output format (json, yaml)")
	huntCmd.Flags().StringVarP(
		&templ,
		"template",
		"t",
		"",
		"set go text/template string for output format",
	)
}
