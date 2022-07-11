package main

import (
	"endpoint-checker/cmd"
	// "github.com/spf13/cobra"
)

func main() {
	// check_cert_date("allliance.ru:443")
	// check_cert_date("icr.ac.uk:443")
	cmd.Execute()
}
