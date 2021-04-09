// Package pillager contains the command line logic
//
// The pillager package is the primary consumer of all packages in the /pkg directory
package pillager

import (
	"runtime"

	hunter2 "github.com/brittonhayes/pillager/pkg/hunter"
	rules2 "github.com/brittonhayes/pillager/pkg/rules"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	verbose     bool
	rulesConfig string
	output      string
	templ       string
	workers     int
)

// huntCmd represents the hunt command
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
	RunE: startHunt(),
}

func init() {
	rootCmd.AddCommand(huntCmd)
	huntCmd.Flags().IntVarP(&workers, "workers", "w", runtime.NumCPU(), "number of concurrent workers to create")
	huntCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "toggle verbose output")
	huntCmd.Flags().StringVarP(&rulesConfig, "rules", "r", "", "path to gitleaks rules.toml config")
	huntCmd.Flags().StringVarP(&output, "format", "f", "json", "set output format (json, yaml)")
	huntCmd.Flags().StringVarP(
		&templ,
		"template",
		"t",
		"",
		"set go text/template string for output format",
	)
}

func startHunt() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		c := hunter2.NewConfig(
			afero.NewOsFs(),
			args[0],
			verbose,
			rules2.Load(rulesConfig),
			hunter2.StringToFormat(output),
			templ,
			workers,
		)
		h := hunter2.NewHunter(c)
		return h.Hunt()
	}
}
