package cmd

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var rootCmd = &cobra.Command{
	Use:   "site",
	Short: "Hugo is a very fast static site generator",
	Long: `A Fast and Flexible Static Site Generator built with
				love by spf13 and friends in Go.
				Complete documentation is available at http://hugo.spf13.com`,
	Run: func(cmd *cobra.Command, args []string) {
		check_cert_date("allliance.ru:433")
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Hugo",
	Long:  `All software has versions. This is Hugo's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Endpoint checker: v0.1")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func check_cert_date(site_address string) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	// conn, err := tls.Dial("tcp", "google.com:443", conf)
	conn, err := tls.Dial("tcp", site_address, conf)

	if err != nil {
		log.Println("Error in Dial", err)
		return
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates

	cert := certs[0].NotAfter.Format("02/01/2006")
	fmt.Println(cert)

	// for _, cert := range certs {
	// 	fmt.Printf("Issuer Name: %s\n", cert.Issuer)
	// 	// fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
	// 	fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("02/01/2006"))
	// 	fmt.Printf("Common Name: %s \n", cert.Issuer.CommonName)
	// }
}

// func Execute() {
// 	if err := rootCmd.Execute(); err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}
// }
