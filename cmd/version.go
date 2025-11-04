package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/potoo0/configurable-http-proxy/lib"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints version",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("%s\n", lib.CHPVersion)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
