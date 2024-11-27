// Package commands contains the command line logic.
//
// The commands package is the primary consumer of all packages in the /pkg directory.
package commands

import (
	"fmt"
	"os"
	"runtime"

	"github.com/brittonhayes/pillager/pkg/scanner"
	"github.com/brittonhayes/pillager/pkg/tui/model"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	dedupe      bool
	entropy     float64
	format      string
	redact      bool
	templ       string
	interactive bool
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
		pillager hunt . --template "{{ range .}}Secret: {{.Secret}}{{end}}"
	
	Custom Go Template Format from Template File:
		pillager hunt ./example --template "$(cat pkg/templates/simple.tmpl)"
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts, err := setupConfig()
		if err != nil {
			return err
		}

		// Get path from args if provided
		if len(args) > 0 {
			opts.Path = args[0]
		}

		// Check if path is provided either via args or config
		if opts.Path == "" {
			return fmt.Errorf("scan path must be provided either as an argument or in the config file")
		}

		s, err := scanner.NewGitleaksScanner(*opts)
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		if interactive {
			return runInteractive(s)
		}

		results, err := s.Scan()
		if err != nil {
			return err
		}

		if len(results) == 0 {
			fmt.Println("[]")
			log.Debug().Msg("no secrets or sensitive information were found at the target directory")
			return nil
		}

		return s.Reporter().Report(os.Stdout, results)
	},
}

func runInteractive(h scanner.Scanner) error {
	m := model.NewModel(h)
	p := tea.NewProgram(m, tea.WithAltScreen())
	return p.Start()
}

func init() {
	rootCmd.AddCommand(huntCmd)

	huntCmd.Flags().StringVarP(&format, "format", "f", "json", "set secret reporter format")
	huntCmd.Flags().BoolVar(&redact, "redact", false, "redact secret from results")
	huntCmd.Flags().StringVarP(&templ, "template", "t", "", "set go text/template string for output format")
	huntCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "run in interactive mode")
	huntCmd.Flags().BoolVarP(&dedupe, "dedupe", "d", false, "deduplicate results")
	huntCmd.Flags().Float64VarP(&entropy, "entropy", "e", 4.0, "minimum entropy value for results")
	huntCmd.Flags().IntVarP(&workers, "workers", "w", runtime.NumCPU(), "number of concurrent workers")

	// Bind flags to viper
	viper.BindPFlag("dedupe", huntCmd.Flags().Lookup("dedupe"))
	viper.BindPFlag("entropy", huntCmd.Flags().Lookup("entropy"))
	viper.BindPFlag("format", huntCmd.Flags().Lookup("format"))
	viper.BindPFlag("redact", huntCmd.Flags().Lookup("redact"))
	viper.BindPFlag("template", huntCmd.Flags().Lookup("template"))
	viper.BindPFlag("workers", huntCmd.Flags().Lookup("workers"))
}
