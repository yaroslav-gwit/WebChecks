package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "endpoint-checker",
	Short: "Endpoint checker is a small program, that checks the health of your webiste",

	Run: func(cmd *cobra.Command, args []string) {
		// Empty function
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
	rootCmd.AddCommand(webCmd)

	// Address flag
	webCmd.Flags().StringVarP(&address, "address", "a", "", "Website address (required)")
	webCmd.Flags().StringVarP(&string_present, "string", "s", "", "Check if this string exists on the page")
	webCmd.MarkFlagsRequiredTogether("address", "string")

	// Port flag
	webCmd.Flags().StringVar(&port, "port", "443", "Website port")
	webCmd.Flags().StringVar(&protocol, "protocol", "https", "Website connection protocol")

	// SSL
	webCmd.Flags().BoolVar(&nossl, "no-ssl", false, "Disable SSL related checks")

	// File flag
	webCmd.Flags().StringVarP(&file_database, "file", "f", "db.json", "Use JSON file database to check multiple servers at once")
	webCmd.MarkFlagsMutuallyExclusive("address", "file")

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
