package cmd

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/table"
	"github.com/spf13/cobra"
)

const red_color = "\033[31m"
const yellow_color = "\033[33m"

const reset_color = "\033[0m"

var (
	address        string
	port           string
	nossl          bool
	protocol       string
	string_present string

	webCmd = &cobra.Command{
		Use:   "web",
		Short: "Web related checks",
		Long:  `Specify the address, port and other bits`,
		Run: func(cmd *cobra.Command, args []string) {
			main()
		},
	}
)

type finalResponseStruct struct {
	website_address string
	cert_end_date   string
	http_status     string
	response_time   string
	string_present  string
}

func main() {
	var response = finalResponseFunc()

	// Create a table
	t := table.New(os.Stdout)
	// Set alignments
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetFooterAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	// Set dividers
	t.SetDividers(table.UnicodeRoundedDividers)
	// Set automerge
	t.SetAutoMerge(true)
	t.SetAutoMergeHeaders(true)
	// Set headers and footers
	t.SetHeaders("ID", "Website address", "Certificate end date", "HTTP status", "Response time (ms)", "String present")
	// t.SetFooters("ID", "Website address", "Certificate end date")

	// Start adding table rows
	var id_number = 1
	var id_string = strconv.Itoa(id_number)
	t.AddRow(id_string, response.website_address, response.cert_end_date, response.http_status, response.response_time, response.string_present)

	// For every next table row execute this:
	// id_number = id_number + 1
	// id_string = strconv.Itoa(id_number)
	// t.AddRow(id_string, "1", "1")

	// Render the table to screen
	t.Render()

}

func finalResponseFunc() finalResponseStruct {
	var check_cert_date_var string
	var website_address_var = address

	if !nossl {
		check_cert_date_var = check_cert_date(address, port)
	} else {
		check_cert_date_var = "N/A"
	}

	var check_response_code_var = check_response_code(address, port, protocol)
	var check_response_time_var = check_response_time(address, port, protocol)
	var check_for_string_var = check_for_string(address, port, protocol, string_present)

	var responseVar = finalResponseStruct{}
	responseVar.cert_end_date = check_cert_date_var
	responseVar.website_address = website_address_var
	responseVar.http_status = check_response_code_var
	responseVar.response_time = check_response_time_var
	responseVar.string_present = check_for_string_var

	return responseVar
}

func check_cert_date(site_address string, port string) string {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	if len(site_address) < 1 {
		var error = "Please specify the site address! Use --help flag to get help"
		fmt.Fprintln(os.Stderr, error)
		os.Exit(1)
	}

	conn, err := tls.Dial("tcp", (site_address + ":" + port), conf)

	if err != nil {
		var error = "FATAL ERROR: Can't access your website -> " + err.Error()
		fmt.Fprintln(os.Stderr, error)
		os.Exit(1)
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates

	var cert_date = certs[0].NotAfter.Format("02/01/2006")

	cert_date = yellow_color + cert_date + reset_color

	return cert_date

	// for _, cert := range certs {
	// 	fmt.Printf("Issuer Name: %s\n", cert.Issuer)
	//  fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
	// 	fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("02/01/2006"))
	// 	fmt.Printf("Common Name: %s \n", cert.Issuer.CommonName)
	// }
}

func check_response_code(site_address, port, protocol string) string {
	resp, err := http.Get(protocol + "://" + site_address + ":" + port)

	if err != nil {
		var error = "FATAL ERROR: Can't access your website -> " + err.Error()
		fmt.Fprintln(os.Stderr, error)
		os.Exit(1)
	}

	defer resp.Body.Close()

	var status_code = strconv.Itoa(resp.StatusCode)
	return status_code
}

func check_response_time(site_address, port, protocol string) string {
	var start_time = time.Now()

	http_client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := http_client.Get(protocol + "://" + site_address + ":" + port)

	if err != nil {
		var error = "FATAL ERROR: Can't access your website -> " + err.Error()
		fmt.Fprintln(os.Stderr, error)
		os.Exit(1)
	}

	defer resp.Body.Close()
	var time_elapsed = strconv.FormatInt(time.Since(start_time).Milliseconds(), 10)

	return time_elapsed
}

func check_for_string(site_address, port, protocol, string_to_look_for string) string {
	http_client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := http_client.Get(protocol + "://" + site_address + ":" + port)
	if err != nil {
		var error = "FATAL ERROR: Can't access your website -> " + err.Error()
		fmt.Fprintln(os.Stderr, error)
		os.Exit(1)
	}
	defer resp.Body.Close()
	// Create and modify HTTP request before sending
	// request, err := http.NewRequest("GET", (protocol + "://" + site_address + ":" + port), nil)
	// request.Header.Set("User-Agent", "Not Firefox")

	// Make request
	dataInBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		var error = "FATAL ERROR: Can't access your website -> " + err.Error()
		fmt.Fprintln(os.Stderr, error)
		os.Exit(1)
	}

	var pageContent = string(dataInBytes)
	var number_of_strings_present = strings.Index(pageContent, string_to_look_for)

	var string_present string

	if number_of_strings_present == -1 {
		string_present = red_color + "Not present!" + reset_color
	} else {
		string_present = "Yes"
	}

	return string_present
}
