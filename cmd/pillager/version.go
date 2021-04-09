package pillager

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var version = "x.x.x"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of Pillager",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("pillager v%s\n", version)
	},
}
