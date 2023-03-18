package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "webchecks",
	Short: "WebChecks is a small set of HTTP/s, SSL, and some other web related checks",

	Run: func(cmd *cobra.Command, args []string) {
		err := cmd.Help()
		if err != nil {
			log.Fatal(err.Error())
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Website related checks
	rootCmd.AddCommand(cliCmd)

	// Output JSON to the screen
	cliCmd.Flags().BoolVar(&jsonOutput, "json", false, "Use JSON output instead of table output. Useful for passing to other programs")
	cliCmd.Flags().BoolVar(&saveResults, "save-results", false, "Save JSON results to a file")
	cliCmd.Flags().StringVar(&resultsFile, "results-file", "/tmp/results.json", "Optionally set the location of the file to save the results to")

	// File flag
	cliCmd.Flags().StringVarP(&fileDatabase, "file", "f", "db.json", "Use JSON file database to check multiple servers at once")

	// Mutually exclusive flags
	// cliCmd.MarkFlagsMutuallyExclusive("file", "address")

	// Print version
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of the endpoint checker",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Endpoint checker: v0.1")
	},
}
