package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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
	file_database  string

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

type jsonInputStruct []struct {
	SiteAddress string `json:"site_address,omitempty"`
	Port        string `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	String      string `json:"string,omitempty"`
}

func jsonInputFileFunc() jsonInputStruct {
	// content, err := ioutil.ReadFile("db.json.example")
	content, err := ioutil.ReadFile(file_database)

	if err != nil {
		log.Fatal(err)
	}

	var json_data_var = jsonInputStruct{}
	json.Unmarshal([]byte(content), &json_data_var)

	return json_data_var
}

func main() {

	if len(address) > 0 {
		// var error = "Please specify the site address! Use --help flag to get help"
		// fmt.Fprintln(os.Stderr, error)
		// os.Exit(1)
		render_table_signle()
	} else {
		render_table_multi()
	}

}

func render_table_multi() {
	var site_list = jsonInputFileFunc()
	var id_number = 1

	// Create a table
	t := table.New(os.Stdout)
	// Set alignments
	t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetFooterAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	// Set dividers
	t.SetDividers(table.UnicodeRoundedDividers)
	// Set automerge
	// t.SetAutoMerge(true)
	t.SetAutoMergeHeaders(true)
	// Set headers and footers
	t.SetHeaders("ID", "Website address", "Certificate end date", "HTTP status", "Response time (ms)", "String present")
	// t.SetFooters("ID", "Website address", "Certificate end date")

	for _, site := range site_list {
		var check_cert_date_var string
		var website_address_var = site.SiteAddress
		var website_port_var = site.Port
		var website_protocol_var = site.Protocol
		var website_string_var = site.String

		if website_protocol_var == "http" {
			check_cert_date_var = "N/A"
		} else if !nossl {
			check_cert_date_var = check_cert_date(website_address_var, website_port_var)
		} else {
			check_cert_date_var = "N/A"
		}

		var check_response_code_var = check_response_code(website_address_var, website_port_var, website_protocol_var)
		var check_response_time_var = check_response_time(website_address_var, website_port_var, website_protocol_var)
		var check_for_string_var = check_for_string(website_address_var, website_port_var, website_protocol_var, website_string_var)

		var responseVar = finalResponseStruct{}
		responseVar.cert_end_date = check_cert_date_var
		responseVar.website_address = website_address_var
		responseVar.http_status = check_response_code_var
		responseVar.response_time = check_response_time_var
		responseVar.string_present = check_for_string_var

		// Start adding table rows
		id_number = id_number + 1
		var id_string = strconv.Itoa(id_number)
		t.AddRow(id_string, responseVar.website_address, responseVar.cert_end_date, responseVar.http_status, responseVar.response_time, responseVar.string_present)
	}
	// Render the table to screen
	t.Render()
}

func render_table_signle() {
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
	http_client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, _ := http.NewRequest("GET", (protocol + "://" + site_address + ":" + port), nil)
	req.Host = site_address
	resp, err := http_client.Do(req)

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
		Timeout: 10 * time.Second,
	}

	req, _ := http.NewRequest("GET", (protocol + "://" + site_address + ":" + port), nil)
	req.Host = site_address
	resp, err := http_client.Do(req)

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
		Timeout: 10 * time.Second,
	}

	req, _ := http.NewRequest("GET", (protocol + "://" + site_address + ":" + port), nil)
	req.Host = site_address
	resp, err := http_client.Do(req)

	if err != nil {
		var error = "FATAL ERROR: Can't access your website -> " + err.Error()
		fmt.Fprintln(os.Stderr, error)
		os.Exit(1)
	}

	defer resp.Body.Close()

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
