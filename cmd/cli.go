package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
	fileDatabase string
	jsonOutput   bool
	saveResults  bool
	resultsFile  string

	cliCmd = &cobra.Command{
		Use:   "cli",
		Short: "WebChecks in a terminal",
		Long:  `Run WebChecks in a terminal window to get the response times, SSL expiry dates and other info`,
		Run: func(cmd *cobra.Command, args []string) {
			main()
		},
	}
)

type certData struct {
	status               string
	daysBeforeExpiration string
	date                 string
}

type finalResponseStruct struct {
	websiteAddress string
	certEndDate    struct {
		status                 string
		days_before_expiration string
		date                   string
	}
	httpStatus     string
	response_time  string
	string_present string
}

type jsonInputStruct []struct {
	Host               string `json:"host,omitempty"`
	SiteAddress        string `json:"site_address"`
	Port               string `json:"port"`
	Protocol           string `json:"protocol"`
	String             string `json:"string"`
	PageToCheck        string `json:"page,omitempty"`
	YellowResponseTime string `json:"yellow_response_time,omitempty"`
	RedResponseTime    string `json:"red_response_time,omitempty"`
	SslAlertTime       int    `json:"amber_days,omitempty"`
}

type jsonOutputStruct struct {
	ID                 string `json:"id,omitempty"`
	Host               string `json:"host,omitempty"`
	SiteAddress        string `json:"site_address,omitempty"`
	PageChecked        string `json:"page_checked,omitempty"`
	Page               string `json:"page,omitempty"`
	HttpStatus         string `json:"http_status,omitempty"`
	ResponseTime       string `json:"response_time,omitempty"`
	YellowResponseTime bool   `json:"yellow_response_time,omitempty"`
	RedResponseTime    bool   `json:"red_response_time,omitempty"`
	StringPresent      string `json:"string_present,omitempty"`
	StringChecked      string `json:"string_checked,omitempty"`
	CertEndDate        string `json:"cert_end_date,omitempty"`
	CertDaysBeforeEnd  string `json:"cert_days_left,omitempty"`
	CertStatus         string `json:"cert_status,omitempty"`
}

func main() {
	if jsonOutput {
		var sites = jsonOutputFuncMulti()
		var jsonData, _ = json.MarshalIndent(sites, "", "   ")
		// Save results to a file
		if saveResults {
			err := os.WriteFile("/tmp/results.json", jsonData, 0644)
			if err != nil {
				panic(err)
			}
		}
		// Print results to a screen
		var json_string = string(jsonData)
		fmt.Println(json_string)
	} else {
		renderTableMulti()
	}
}

func readConfigFile() jsonInputStruct {
	// Read and parse JSON DB file
	content, err := os.ReadFile(fileDatabase)
	if err != nil {
		log.Fatal(err)
	}

	jsonData := jsonInputStruct{}
	err = json.Unmarshal([]byte(content), &jsonData)
	if err != nil {
		// return err
		log.Fatal(err)
	}

	for _, site := range jsonData {
		if site.SslAlertTime == 0 || site.SslAlertTime < 1 {
			site.SslAlertTime = 30
		}
	}

	return jsonData
}

func jsonOutputFuncMulti() []jsonOutputStruct {
	var jsonOutput = jsonOutputStruct{}
	var jsonFileInput = readConfigFile()
	var idNumber = 0

	var sites = []jsonOutputStruct{}

	var barDescription = "Working..."

	var bar = progressbar.NewOptions(len(jsonFileInput),
		progressbar.OptionSetWidth(60),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetDescription(barDescription),
	)

	for _, site := range jsonFileInput {
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
			certDataVar.daysBeforeExpiration = "N/A"
		} else {
			certDataVar = checkCertDate(website_address_var, site.Port, site.Protocol, site.SslAlertTime)
		}

		var check_response_code_var = checkResponseCode(website_address_var, website_port_var, website_protocol_var)
		var check_response_time_var = checkResponseTime(website_address_var, website_port_var, website_protocol_var)
		var check_for_string_var = checkForString(website_address_var, website_port_var, website_protocol_var, website_string_var, pageToCheck)

		var responseVar = finalResponseStruct{}
		responseVar.certEndDate.status = certDataVar.status
		responseVar.certEndDate.date = certDataVar.date
		responseVar.certEndDate.days_before_expiration = certDataVar.daysBeforeExpiration

		responseVar.websiteAddress = website_address_var
		responseVar.httpStatus = check_response_code_var
		responseVar.response_time = check_response_time_var
		responseVar.string_present = check_for_string_var

		idNumber = idNumber + 1
		var id_string = strconv.Itoa(idNumber)
		jsonOutput.ID = id_string
		jsonOutput.SiteAddress = responseVar.websiteAddress
		jsonOutput.PageChecked = website_protocol_var + "://" + website_address_var + ":" + website_port_var + page
		jsonOutput.HttpStatus = responseVar.httpStatus
		jsonOutput.ResponseTime = responseVar.response_time
		jsonOutput.StringPresent = responseVar.string_present
		jsonOutput.CertStatus = responseVar.certEndDate.status
		jsonOutput.CertEndDate = responseVar.certEndDate.date
		jsonOutput.CertDaysBeforeEnd = responseVar.certEndDate.days_before_expiration
		jsonOutput.Host = host
		jsonOutput.Page = page
		jsonOutput.StringChecked = stringChecked
		sites = append(sites, jsonOutput)

		if err := bar.Add(1); err != nil {
			log.Fatal("Can't spawn the progress bar: " + err.Error())
		}
	}

	return sites
}

func renderTableMulti() {
	var site_list = readConfigFile()
	var bar_description = "Working... "
	var id_number = 0

	var bar = progressbar.NewOptions(len(site_list),
		progressbar.OptionSetWidth(60),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetDescription(bar_description),
	)

	// Create a table
	t := table.New(os.Stdout)
	t.SetAlignment(table.AlignCenter, table.AlignLeft, table.AlignLeft, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignLeft)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAutoMergeHeaders(true)

	// Set headers and footers
	var headerID = boldFont + "ID" + resetStyle
	var headerHost = boldFont + "Host" + resetStyle
	var headerWebsiteAddress = boldFont + "Website address" + resetStyle
	var headerCertificateEndDate = boldFont + "Certificate end date" + resetStyle
	var headerHttpStatus = boldFont + "HTTP status" + resetStyle
	var headerResponseTime = boldFont + "Response time (ms)" + resetStyle
	var headerStringChecked = boldFont + "String Check" + resetStyle
	t.SetHeaders(headerID, headerHost, headerWebsiteAddress, headerCertificateEndDate, headerHttpStatus, headerResponseTime, headerStringChecked)
	t.SetLineStyle(table.StyleBrightCyan)

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

		checkCertDateVar := checkCertDate(website_address_var, website_port_var, website_protocol_var, site.SslAlertTime)

		var check_response_code_var = checkResponseCode(website_address_var, website_port_var, website_protocol_var)
		var check_response_time_var = checkResponseTime(website_address_var, website_port_var, website_protocol_var)
		var check_for_string_var = checkForString(website_address_var, website_port_var, website_protocol_var, website_string_var, pageToCheck)

		var responseVar = finalResponseStruct{}
		responseVar.certEndDate.date = checkCertDateVar.date

		if checkCertDateVar.status == "yellow" {
			responseVar.certEndDate.date = yellowColor + responseVar.certEndDate.date + resetStyle
		} else if checkCertDateVar.status == "red" {
			responseVar.certEndDate.date = redColor + responseVar.certEndDate.date + resetStyle
		}

		responseVar.websiteAddress = website_address_var
		responseVar.httpStatus = check_response_code_var
		responseVar.response_time = check_response_time_var

		var websitePageChecked = website_protocol_var + "://" + website_address_var + ":" + website_port_var + page

		var stringPresent string
		if check_for_string_var == "Yes" {
			stringPresent = " (present)"
		} else {
			stringPresent = redColor + " (missing)" + resetStyle
		}
		var stringCheck = stringChecked + stringPresent

		// Start adding table rows
		id_number = id_number + 1
		var id_string = strconv.Itoa(id_number)
		t.AddRow(id_string, host, websitePageChecked, responseVar.certEndDate.date, responseVar.httpStatus, responseVar.response_time, stringCheck)

		if err := bar.Add(1); err != nil {
			log.Fatal("Can't spawn the progress bar: " + err.Error())
		}
	}

	// Render the table to screen
	t.Render()
}

func checkCertDate(site_address string, port string, protocol string, sslAmberDays int) certData {
	if site_address == "" {
		log.Fatal("Site address was not specified!")
	}

	var certDataVar = certData{}

	if protocol != "https" {
		certDataVar.date = "N/A"
		certDataVar.status = "N/A"
		certDataVar.daysBeforeExpiration = "N/A"
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
		certDataVar.daysBeforeExpiration = "N/A"
		return certDataVar
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates

	var cert_status string
	var cert_date = certs[0].NotAfter.Format("02/01/2006")
	var daysUntilExp = (time.Since(certs[0].NotAfter).Hours() / float64(sslAmberDays)) * -1
	var daysUntilExpStr = fmt.Sprintf("%.0f", daysUntilExp)

	var ember_cert_status = time.Now().AddDate(0, 0, +sslAmberDays)

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
	certDataVar.daysBeforeExpiration = daysUntilExpStr

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
		fmt.Println("\nERR_IN_FUNC: check_for_string: " + err.Error())
		return "ERROR"
	}

	defer resp.Body.Close()

	// dataInBytes, err := ioutil.ReadAll(resp.Body)
	dataInBytes, err := io.ReadAll(resp.Body)
	if err != nil {
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
