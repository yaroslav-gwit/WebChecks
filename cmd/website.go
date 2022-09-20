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
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

const redColor = "\033[31m"
const yellowColor = "\033[33m"
const boldFont = "\033[1m"
const resetStyle = "\033[0m"

var (
	address        string
	port           string
	protocol       string
	string_present string
	file_database  string
	json_output    bool
	save_results   bool
	results_file   string
	pageToCheck    string

	webCmd = &cobra.Command{
		Use:   "web",
		Short: "Web related checks",
		Long:  `Specify the address, port and other bits`,
		Run: func(cmd *cobra.Command, args []string) {
			main()
		},
	}
)

type certData struct {
	status                 string
	days_before_expiration string
	date                   string
}

type finalResponseStruct struct {
	website_address string
	cert_end_date   struct {
		status                 string
		days_before_expiration string
		date                   string
	}
	http_status    string
	response_time  string
	string_present string
}

type jsonInputStruct []struct {
	Host        string `json:"host,omitempty"`
	SiteAddress string `json:"site_address,omitempty"`
	Port        string `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	String      string `json:"string,omitempty"`
	PageToCheck string `json:"page,omitempty"`
}

type jsonOutputStruct struct {
	ID                string `json:"id,omitempty"`
	Host              string `json:"host,omitempty"`
	SiteAddress       string `json:"site_address,omitempty"`
	Page              string `json:"page,omitempty"`
	HttpStatus        string `json:"http_status,omitempty"`
	ResponseTime      string `json:"response_time,omitempty"`
	StringPresent     string `json:"string_present,omitempty"`
	StringChecked     string `json:"string_checked,omitempty"`
	CertEndDate       string `json:"cert_end_date,omitempty"`
	CertDaysBeforeEnd string `json:"cert_days_left,omitempty"`
	CertStatus        string `json:"cert_status,omitempty"`
}

func main() {
	// THIS IF checks if the address value was used and outputs single or multi data tables
	if len(address) > 0 {
		// Single site functions
		if json_output {
			var sites = jsonOutputFuncSingle()
			var json_data, _ = json.MarshalIndent(sites, "", "   ")
			// Save results to a file
			if save_results {
				err := os.WriteFile("/tmp/results.json", json_data, 0644)
				if err != nil {
					panic(err)
				}
			}
			// Print results to a screen
			var json_string = string(json_data)
			fmt.Println(json_string)
		} else {
			renderTableSingle()
		}
	} else {
		// Multisite functions
		if json_output {
			var sites = jsonOutputFuncMulti()
			var json_data, _ = json.MarshalIndent(sites, "", "   ")
			// Save results to a file
			if save_results {
				err := os.WriteFile("/tmp/results.json", json_data, 0644)
				if err != nil {
					panic(err)
				}
			}
			// Print results to a screen
			var json_string = string(json_data)
			fmt.Println(json_string)
		} else {
			renderTableMulti()
		}
	}
}

func jsonInputFileFunc() jsonInputStruct {
	// Read and parse JSON DB file
	content, err := ioutil.ReadFile(file_database)

	if err != nil {
		log.Fatal(err)
	}

	var json_data_var = jsonInputStruct{}
	json.Unmarshal([]byte(content), &json_data_var)

	return json_data_var
}

func jsonOutputFuncMulti() []jsonOutputStruct {
	var json_output = jsonOutputStruct{}
	var json_file_input = jsonInputFileFunc()
	var id_number = 0

	var sites = []jsonOutputStruct{}

	var bar_descrition = "Working..."

	var bar = progressbar.NewOptions(len(json_file_input),
		progressbar.OptionSetWidth(60),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetDescription(bar_descrition),
	)

	for _, site := range json_file_input {
		// bar_descrition = site.SiteAddress
		var website_address_var = site.SiteAddress
		var website_port_var = site.Port
		var website_protocol_var = site.Protocol
		var website_string_var = site.String
		var pageToCheck = site.PageToCheck
		var host = site.Host
		var page = site.PageToCheck
		var stringChecked = site.String
		if len(page) < 1 {
			page = "/"
		}

		var certDataVar = certData{}
		if website_protocol_var == "http" {
			certDataVar.date = "N/A"
			certDataVar.status = "N/A"
			certDataVar.days_before_expiration = "N/A"
		} else {
			certDataVar = checkCertDate(address, port, protocol)
		}

		var check_response_code_var = checkResponseCode(website_address_var, website_port_var, website_protocol_var)
		var check_response_time_var = checkResponseTime(website_address_var, website_port_var, website_protocol_var)
		var check_for_string_var = checkForString(website_address_var, website_port_var, website_protocol_var, website_string_var, pageToCheck)

		var responseVar = finalResponseStruct{}
		responseVar.cert_end_date.status = certDataVar.status
		responseVar.cert_end_date.date = certDataVar.date
		responseVar.cert_end_date.days_before_expiration = certDataVar.days_before_expiration

		responseVar.website_address = website_address_var
		responseVar.http_status = check_response_code_var
		responseVar.response_time = check_response_time_var
		responseVar.string_present = check_for_string_var

		id_number = id_number + 1
		var id_string = strconv.Itoa(id_number)
		json_output.ID = id_string
		json_output.SiteAddress = responseVar.website_address
		json_output.HttpStatus = responseVar.http_status
		json_output.ResponseTime = responseVar.response_time
		json_output.StringPresent = responseVar.string_present
		json_output.CertStatus = responseVar.cert_end_date.status
		json_output.CertEndDate = responseVar.cert_end_date.date
		json_output.CertDaysBeforeEnd = responseVar.cert_end_date.days_before_expiration
		json_output.Host = host
		json_output.Page = page
		json_output.StringChecked = stringChecked
		sites = append(sites, json_output)

		bar.Add(1)
	}

	return sites
}

func jsonOutputFuncSingle() jsonOutputStruct {
	var json_output = jsonOutputStruct{}
	var id_number = 0
	var sites = jsonOutputStruct{}

	var info = finalResponseFunc()

	id_number = id_number + 1
	var id_string = strconv.Itoa(id_number)
	json_output.ID = id_string
	json_output.SiteAddress = address
	json_output.HttpStatus = info.http_status
	json_output.ResponseTime = info.response_time
	json_output.StringPresent = info.string_present
	json_output.CertStatus = info.cert_end_date.status
	json_output.CertEndDate = info.cert_end_date.date
	sites = json_output

	return sites
}

func renderTableMulti() {
	var site_list = jsonInputFileFunc()
	var bar_descrition = "Working... "
	var id_number = 0

	var bar = progressbar.NewOptions(len(site_list),
		progressbar.OptionSetWidth(60),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetDescription(bar_descrition),
	)

	// Create a table
	t := table.New(os.Stdout)
	// Set alignments
	// t.SetHeaderAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	// t.SetFooterAlignment(table.AlignLeft, table.AlignLeft, table.AlignLeft)
	t.SetAlignment(table.AlignCenter, table.AlignLeft, table.AlignLeft, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignLeft)
	// Set dividers
	t.SetDividers(table.UnicodeRoundedDividers)
	// Set automerge
	// t.SetAutoMerge(true)
	t.SetAutoMergeHeaders(true)
	// Set headers and footers
	var headerID = boldFont + "ID" + resetStyle
	var headerHost = boldFont + "Host" + resetStyle
	var headerWebsiteAddress = boldFont + "Website address" + resetStyle
	var headerPage = boldFont + "Page" + resetStyle
	var headerCertificateEndDate = boldFont + "Certificate end date" + resetStyle
	var headerHttpStatus = boldFont + "HTTP status" + resetStyle
	var headerResponseTime = boldFont + "Response time (ms)" + resetStyle
	var headerStringPresent = boldFont + "String present" + resetStyle
	var headerStringChecked = boldFont + "String checked" + resetStyle
	t.SetHeaders(headerID, headerHost, headerWebsiteAddress, headerPage, headerCertificateEndDate, headerHttpStatus, headerResponseTime, headerStringPresent, headerStringChecked)
	t.SetLineStyle(table.StyleBrightCyan)
	// t.SetFooters("ID", "Website address", "Certificate end date")

	for _, site := range site_list {
		var website_address_var = site.SiteAddress
		var website_port_var = site.Port
		var website_protocol_var = site.Protocol
		var website_string_var = site.String
		var pageToCheck = site.PageToCheck
		var host = site.Host
		var page = site.PageToCheck
		if len(page) < 1 {
			page = "/"
		}
		var stringChecked = site.String

		var checkCertDateVar = certData{}
		checkCertDateVar = checkCertDate(website_address_var, website_port_var, website_protocol_var)

		var check_response_code_var = checkResponseCode(website_address_var, website_port_var, website_protocol_var)
		var check_response_time_var = checkResponseTime(website_address_var, website_port_var, website_protocol_var)
		var check_for_string_var = checkForString(website_address_var, website_port_var, website_protocol_var, website_string_var, pageToCheck)

		var responseVar = finalResponseStruct{}
		responseVar.cert_end_date.date = checkCertDateVar.date

		if checkCertDateVar.status == "yellow" {
			responseVar.cert_end_date.date = yellowColor + responseVar.cert_end_date.date + resetStyle
		} else if checkCertDateVar.status == "red" {
			responseVar.cert_end_date.date = redColor + responseVar.cert_end_date.date + resetStyle
		}

		responseVar.website_address = website_address_var
		responseVar.http_status = check_response_code_var
		responseVar.response_time = check_response_time_var

		var string_present string
		if check_for_string_var != "Yes" {
			string_present = redColor + check_for_string_var + resetStyle
		} else {
			string_present = check_for_string_var
		}
		responseVar.string_present = string_present

		// Start adding table rows
		id_number = id_number + 1
		var id_string = strconv.Itoa(id_number)
		t.AddRow(id_string, host, responseVar.website_address, page, responseVar.cert_end_date.date, responseVar.http_status, responseVar.response_time, responseVar.string_present, stringChecked)

		bar.Add(1)
	}
	// Render the table to screen
	t.Render()
}

func renderTableSingle() {
	var response = finalResponseFunc()

	var cert_end_date_date string
	if response.cert_end_date.status == "yellow" {
		cert_end_date_date = yellowColor + response.cert_end_date.date + resetStyle
	} else if response.cert_end_date.status == "red" {
		cert_end_date_date = redColor + response.cert_end_date.date + resetStyle
	} else {
		cert_end_date_date = response.cert_end_date.date
	}

	var string_present string
	if response.string_present != "Yes" {
		string_present = redColor + response.string_present + resetStyle
	} else {
		string_present = response.string_present
	}

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
	var headerID = boldFont + "ID" + resetStyle
	var headerWebsiteAddress = boldFont + "Website address" + resetStyle
	var headerCertificateEndDate = boldFont + "Certificate end date" + resetStyle
	var headerHttpStatus = boldFont + "HTTP status" + resetStyle
	var headerResponseTime = boldFont + "Response time (ms)" + resetStyle
	var headerStringPresent = boldFont + "String present" + resetStyle
	t.SetHeaders(headerID, headerWebsiteAddress, headerCertificateEndDate, headerHttpStatus, headerResponseTime, headerStringPresent)
	t.SetLineStyle(table.StyleBrightCyan)
	// t.SetHeaders("ID", "Website address", "Certificate end date", "HTTP status", "Response time (ms)", "String present")
	// t.SetFooters("ID", "Website address", "Certificate end date")

	// Start adding table rows
	var id_number = 1
	var id_string = strconv.Itoa(id_number)
	t.AddRow(id_string, response.website_address, cert_end_date_date, response.http_status, response.response_time, string_present)

	// Render the table to screen
	t.Render()
}

func finalResponseFunc() finalResponseStruct {
	var website_address_var = address
	var checkCertDateVar = certData{}

	checkCertDateVar = checkCertDate(address, port, protocol)

	var check_response_code_var = checkResponseCode(address, port, protocol)
	var check_response_time_var = checkResponseTime(address, port, protocol)
	var check_for_string_var = checkForString(address, port, protocol, string_present, pageToCheck)

	var responseVar = finalResponseStruct{}
	responseVar.cert_end_date.status = checkCertDateVar.status
	responseVar.cert_end_date.date = checkCertDateVar.date
	responseVar.cert_end_date.days_before_expiration = checkCertDateVar.days_before_expiration
	responseVar.website_address = website_address_var
	responseVar.http_status = check_response_code_var
	responseVar.response_time = check_response_time_var
	responseVar.string_present = check_for_string_var

	return responseVar
}

func checkCertDate(site_address string, port string, protocol string) certData {
	var certDataVar = certData{}

	if protocol != "https" {
		certDataVar.date = "N/A"
		certDataVar.status = "N/A"
		certDataVar.days_before_expiration = "N/A"
		return certDataVar
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", (site_address + ":" + port), conf)
	if err != nil {
		// var error = "CERT_DATE FATAL ERROR: Can't access your website -> " + err.Error()
		// fmt.Fprintln(os.Stderr, error)
		// os.Exit(1)
		fmt.Println("\nERR_IN_FUNC: check_cert_date: " + err.Error())
		certDataVar.date = "N/A"
		certDataVar.status = "N/A"
		certDataVar.days_before_expiration = "N/A"
		return certDataVar
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates

	var cert_status string
	var cert_date = certs[0].NotAfter.Format("02/01/2006")
	var daysUntilExp = (time.Since(certs[0].NotAfter).Hours() / 24.0) * -1
	var daysUntilExpStr = fmt.Sprintf("%.0f", daysUntilExp)

	var ember_cert_status = time.Now().AddDate(0, 0, +20)

	if ember_cert_status.Before(certs[0].NotAfter) {
		cert_status = "green"
	} else if ember_cert_status == certs[0].NotAfter {
		cert_status = "green"
	} else if time.Now() == certs[0].NotAfter {
		cert_status = "red"
	} else if time.Now().After(certs[0].NotAfter) {
		cert_status = "red"
	} else {
		cert_status = "yellow"
	}

	certDataVar.status = cert_status
	certDataVar.date = cert_date
	certDataVar.days_before_expiration = daysUntilExpStr
	fmt.Println(certDataVar)

	return certDataVar
}

func checkResponseCode(site_address, port, protocol string) string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	http_client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	req, _ := http.NewRequest("GET", (protocol + "://" + site_address + ":" + port), nil)
	req.Host = site_address
	resp, err := http_client.Do(req)

	if err != nil {
		// var error = "RESPONSE_CODE FATAL ERROR: Can't access your website -> " + err.Error()
		// fmt.Fprintln(os.Stderr, error)
		// os.Exit(1)
		fmt.Println("\nERR_IN_FUNC: check_response_code: " + err.Error())
		return "ERROR"
	}

	defer resp.Body.Close()

	var status_code = strconv.Itoa(resp.StatusCode)
	return status_code
}

func checkResponseTime(site_address, port, protocol string) string {
	var start_time = time.Now()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	http_client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	req, _ := http.NewRequest("GET", (protocol + "://" + site_address + ":" + port), nil)
	req.Host = site_address
	resp, err := http_client.Do(req)

	if err != nil {
		// var error = "CHECK_RESPONSE_TIME FATAL ERROR: Can't access your website -> " + err.Error()
		// fmt.Fprintln(os.Stderr, error)
		// os.Exit(1)
		fmt.Println("\nERR_IN_FUNC: check_response_time: " + err.Error())
		return "ERROR"
	}

	defer resp.Body.Close()
	var time_elapsed = strconv.FormatInt(time.Since(start_time).Milliseconds(), 10)

	return time_elapsed
}

func checkForString(site_address, port, protocol, string_to_look_for, pageToCheck string) string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	http_client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}

	if len(pageToCheck) < 1 {
		pageToCheck = "/"
	}

	req, _ := http.NewRequest("GET", (protocol + "://" + site_address + ":" + port + pageToCheck), nil)
	req.Host = site_address
	resp, err := http_client.Do(req)

	if err != nil {
		// var error = "FATAL ERROR: Can't access your website -> " + err.Error()
		// fmt.Fprintln(os.Stderr, error)
		// os.Exit(1)
		fmt.Println("\nERR_IN_FUNC: check_for_string: " + err.Error())
		return "ERROR"
	}

	defer resp.Body.Close()

	dataInBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// var error = "CHECK_FOR_STRING FATAL ERROR: Can't access your website -> " + err.Error()
		// fmt.Fprintln(os.Stderr, error)
		// os.Exit(1)
		fmt.Println("\nERR_IN_FUNC: check_for_string: " + err.Error())
		return "ERROR"
	}

	var pageContent = string(dataInBytes)
	var number_of_strings_present = strings.Index(pageContent, string_to_look_for)

	var string_present string

	if number_of_strings_present == -1 {
		string_present = "Not present!"
	} else {
		string_present = "Yes"
	}

	return string_present
}
