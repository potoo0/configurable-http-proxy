package cmd

import (
	"fmt"
	"github.com/potoo0/configurable-http-proxy/lib"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", lib.CHPVersion)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
