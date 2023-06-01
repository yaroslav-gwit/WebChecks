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
		status               string
		daysBeforeExpiration string
		date                 string
	}
	httpStatus    string
	responseTime  string
	stringPresent bool
}

type jsonInputStruct []struct {
	Host               string `json:"host,omitempty"`
	SiteAddress        string `json:"site_address"`
	Port               string `json:"port"`
	Protocol           string `json:"protocol"`
	String             string `json:"string"`
	PageToCheck        string `json:"page,omitempty"`
	YellowResponseTime int    `json:"yellow_response_time,omitempty"`
	RedResponseTime    int    `json:"red_response_time,omitempty"`
	SslAlertTime       int    `json:"amber_days"`
}

type jsonOutputStruct struct {
	ID                 string `json:"id,omitempty"`
	Host               string `json:"host,omitempty"`
	SiteAddress        string `json:"site_address,omitempty"`
	PageChecked        string `json:"page_checked,omitempty"`
	Page               string `json:"page,omitempty"`
	HttpStatus         string `json:"http_status,omitempty"`
	ResponseTime       string `json:"response_time,omitempty"`
	YellowResponseTime bool   `json:"yellow_response_time"`
	RedResponseTime    bool   `json:"red_response_time"`
	StringPresent      bool   `json:"string_present"`
	StringChecked      string `json:"string_checked,omitempty"`
	CertEndDate        string `json:"cert_end_date,omitempty"`
	CertDaysBeforeEnd  string `json:"cert_days_left,omitempty"`
	CertStatus         string `json:"cert_status,omitempty"`
}

func main() {
	if jsonOutput {
		sites := jsonOutputFuncMulti()
		jsonData, _ := json.MarshalIndent(sites, "", "   ")
		if saveResults {
			err := os.WriteFile("/tmp/results.json", jsonData, 0644)
			if err != nil {
				panic(err)
			}
		}
		jsonString := string(jsonData)
		fmt.Println(jsonString)
	} else {
		renderTableMulti()
	}
}

func readConfigFile() jsonInputStruct {
	var content []byte
	var err error
	_, err = os.Stat(fileDatabase)
	if os.IsNotExist(err) {
		_, optDbFileErr := os.Stat("/opt/webchecks/db.json")
		if os.IsNotExist(optDbFileErr) {
			log.Fatal("File doesn't exist! /opt/webchecks/db.json")
		}
		content, err = os.ReadFile("/opt/webchecks/db.json")
		if err != nil {
			log.Fatal(err)
		}
	} else {
		content, err = os.ReadFile(fileDatabase)
		if err != nil {
			log.Fatal(err)
		}
	}

	jsonData := jsonInputStruct{}
	err = json.Unmarshal([]byte(content), &jsonData)
	if err != nil {
		log.Fatal(err)
	}

	for i, v := range jsonData {
		if v.SslAlertTime <= 0 {
			jsonData[i].SslAlertTime = 30
		}
		if v.YellowResponseTime <= 0 {
			jsonData[i].YellowResponseTime = 200
		}
		if v.RedResponseTime <= 0 {
			jsonData[i].RedResponseTime = 500
		}
	}

	return jsonData
}

func jsonOutputFuncMulti() []jsonOutputStruct {
	jsonOutput := jsonOutputStruct{}
	jsonFileInput := readConfigFile()
	idNumber := 0
	sites := []jsonOutputStruct{}

	barDescription := "Working..."
	bar := progressbar.NewOptions(len(jsonFileInput),
		progressbar.OptionSetWidth(60),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetDescription(barDescription),
	)

	for _, site := range jsonFileInput {
		websiteAddressVar := site.SiteAddress
		websitePortVar := site.Port
		websiteProtocolVar := site.Protocol
		websiteStringVar := site.String
		pageToCheck := site.PageToCheck
		host := site.Host
		page := site.PageToCheck
		stringChecked := site.String

		if len(page) < 1 {
			page = "/"
		}

		certDataVar := certData{}
		if websiteProtocolVar == "http" {
			certDataVar.date = "N/A"
			certDataVar.status = "N/A"
			certDataVar.daysBeforeExpiration = "N/A"
		} else {
			certDataVar = checkCertDate(websiteAddressVar, site.Port, site.Protocol, site.SslAlertTime)
		}

		// checkResponseCodeVar := checkResponseCode(websiteAddressVar, websitePortVar, websiteProtocolVar)
		checkResponseTimeVar, _ := checkResponseTime(websiteAddressVar, websitePortVar, websiteProtocolVar, site.RedResponseTime, site.YellowResponseTime)
		checkForStringVar, checkResponseCodeVar := checkForString(websiteAddressVar, websitePortVar, websiteProtocolVar, websiteStringVar, pageToCheck)

		responseVar := finalResponseStruct{}
		responseVar.certEndDate.status = certDataVar.status
		responseVar.certEndDate.date = certDataVar.date
		responseVar.certEndDate.daysBeforeExpiration = certDataVar.daysBeforeExpiration

		responseVar.websiteAddress = websiteAddressVar
		responseVar.httpStatus = checkResponseCodeVar
		responseVar.responseTime = checkResponseTimeVar.time
		responseVar.stringPresent = checkForStringVar

		idNumber = idNumber + 1
		idString := strconv.Itoa(idNumber)
		jsonOutput.ID = idString
		jsonOutput.SiteAddress = responseVar.websiteAddress
		jsonOutput.PageChecked = websiteProtocolVar + "://" + websiteAddressVar + ":" + websitePortVar + page
		jsonOutput.HttpStatus = responseVar.httpStatus
		jsonOutput.ResponseTime = checkResponseTimeVar.time
		jsonOutput.YellowResponseTime = checkResponseTimeVar.yellow
		jsonOutput.RedResponseTime = checkResponseTimeVar.red
		jsonOutput.StringPresent = responseVar.stringPresent
		jsonOutput.CertStatus = responseVar.certEndDate.status
		jsonOutput.CertEndDate = responseVar.certEndDate.date
		jsonOutput.CertDaysBeforeEnd = responseVar.certEndDate.daysBeforeExpiration
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
	siteList := readConfigFile()
	barDescription := "Working... "
	idNumber := 0

	bar := progressbar.NewOptions(len(siteList),
		progressbar.OptionSetWidth(60),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetDescription(barDescription),
	)

	t := table.New(os.Stdout)
	t.SetAlignment(table.AlignCenter, table.AlignLeft, table.AlignLeft, table.AlignCenter, table.AlignCenter, table.AlignCenter, table.AlignLeft)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAutoMergeHeaders(true)
	headerID := boldFont + "ID" + resetStyle
	headerHost := boldFont + "Host" + resetStyle
	headerWebsiteAddress := boldFont + "Website address" + resetStyle
	headerCertificateEndDate := boldFont + "Certificate end date" + resetStyle
	headerHttpStatus := boldFont + "HTTP status" + resetStyle
	headerResponseTime := boldFont + "Response time (ms)" + resetStyle
	headerStringChecked := boldFont + "String Check" + resetStyle
	t.SetHeaders(headerID, headerHost, headerWebsiteAddress, headerCertificateEndDate, headerHttpStatus, headerResponseTime, headerStringChecked)
	t.SetLineStyle(table.StyleBrightCyan)

	for _, site := range siteList {
		websiteAddressVar := site.SiteAddress
		websitePortVar := site.Port
		websiteProtocolVar := site.Protocol
		websiteStringVar := site.String

		pageToCheck := site.PageToCheck
		host := site.Host
		page := site.PageToCheck
		if len(page) < 1 {
			page = "/"
		}
		stringChecked := site.String

		checkCertDateVar := checkCertDate(websiteAddressVar, websitePortVar, websiteProtocolVar, site.SslAlertTime)
		// checkResponseCodeVar := checkResponseCode(websiteAddressVar, websitePortVar, websiteProtocolVar)
		checkResponseTimeVar, _ := checkResponseTime(websiteAddressVar, websitePortVar, websiteProtocolVar, site.RedResponseTime, site.YellowResponseTime)
		checkForStringVar, checkResponseCodeVar := checkForString(websiteAddressVar, websitePortVar, websiteProtocolVar, websiteStringVar, pageToCheck)

		responseVar := finalResponseStruct{}
		responseVar.certEndDate.date = checkCertDateVar.date

		if checkCertDateVar.status == "yellow" {
			responseVar.certEndDate.date = yellowColor + responseVar.certEndDate.date + resetStyle
		} else if checkCertDateVar.status == "red" {
			responseVar.certEndDate.date = redColor + responseVar.certEndDate.date + resetStyle
		}

		responseVar.websiteAddress = websiteAddressVar
		responseVar.httpStatus = checkResponseCodeVar
		if checkResponseTimeVar.yellow {
			checkResponseTimeVar.time = yellowColor + checkResponseTimeVar.time + resetStyle
		}
		if checkResponseTimeVar.red {
			checkResponseTimeVar.time = redColor + checkResponseTimeVar.time + resetStyle
		}
		websitePageChecked := websiteProtocolVar + "://" + websiteAddressVar + ":" + websitePortVar + page

		var stringPresent string
		if checkForStringVar {
			stringPresent = " (present)"
		} else {
			stringPresent = redColor + " (missing)" + resetStyle
		}
		stringCheck := stringChecked + stringPresent

		idNumber = idNumber + 1
		idString := strconv.Itoa(idNumber)
		t.AddRow(idString, host, websitePageChecked, responseVar.certEndDate.date, responseVar.httpStatus, checkResponseTimeVar.time, stringCheck)
		if err := bar.Add(1); err != nil {
			log.Fatal("Can't spawn the progress bar: " + err.Error())
		}
	}
	t.Render()
}

func checkCertDate(siteAddress string, port string, protocol string, sslAmberDays int) certData {
	if siteAddress == "" {
		log.Fatal("Site address was not specified!")
	}
	certDataVar := certData{}
	if protocol != "https" {
		certDataVar.date = "N/A"
		certDataVar.status = "N/A"
		certDataVar.daysBeforeExpiration = "N/A"
		return certDataVar
	}

	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", (siteAddress + ":" + port), conf)
	if err != nil {
		fmt.Println("\nERR_IN_FUNC: check_cert_date: " + err.Error())
		certDataVar.date = "N/A"
		certDataVar.status = "N/A"
		certDataVar.daysBeforeExpiration = "N/A"
		return certDataVar
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates

	var certStatus string
	certDate := certs[0].NotAfter.Format("02/01/2006")
	daysUntilExp := (time.Since(certs[0].NotAfter).Hours() / float64(sslAmberDays)) * -1
	daysUntilExpStr := fmt.Sprintf("%.0f", daysUntilExp)

	emberCertStatus := time.Now().AddDate(0, 0, +sslAmberDays)
	if emberCertStatus.Before(certs[0].NotAfter) {
		certStatus = "green"
	} else if emberCertStatus == certs[0].NotAfter {
		certStatus = "green"
	} else if time.Now() == certs[0].NotAfter {
		certStatus = "red"
	} else if time.Now().After(certs[0].NotAfter) {
		certStatus = "red"
	} else {
		certStatus = "yellow"
	}

	certDataVar.status = certStatus
	certDataVar.date = certDate
	certDataVar.daysBeforeExpiration = daysUntilExpStr

	return certDataVar
}

// func checkResponseCode(siteAddress, port, protocol string) string {
// 	tr := &http.Transport{
// 		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
// 	}

// 	httpClient := &http.Client{
// 		Timeout:   10 * time.Second,
// 		Transport: tr,
// 	}

// 	req, _ := http.NewRequest("GET", (protocol + "://" + siteAddress + ":" + port), nil)
// 	req.Host = siteAddress
// 	resp, err := httpClient.Do(req)

// 	if err != nil {
// 		fmt.Println("\nERR_IN_FUNC: check_response_code: " + err.Error())
// 		return "ERROR"
// 	}

// 	defer resp.Body.Close()
// 	return strconv.Itoa(resp.StatusCode)
// }

type ResponseTime struct {
	time   string
	red    bool
	yellow bool
}

// Returns response time and response code
func checkResponseTime(siteAddress string, port string, protocol string, redResponseTime int, yellowResponseTime int) (ResponseTime, string) {
	startTime := time.Now()
	responseTime := ResponseTime{}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{
		Timeout:   6 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", (protocol + "://" + siteAddress + ":" + port), nil)
	if err != nil {
		fmt.Println("\nERR_IN_FUNC: check_response_time: " + err.Error())
		responseTime.time = "ERROR"
		return responseTime, "ERROR"
	}
	req.Host = siteAddress
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("\nERR_IN_FUNC: check_response_time: " + err.Error())
		responseTime.time = "ERROR"
		return responseTime, "ERROR"
	}
	defer resp.Body.Close()

	rTime := time.Since(startTime).Milliseconds()
	responseTime.time = strconv.FormatInt(rTime, 10)
	if rTime > int64(yellowResponseTime) {
		responseTime.yellow = true
	}
	if rTime > int64(redResponseTime) {
		responseTime.red = true
	}

	return responseTime, strconv.Itoa(resp.StatusCode)
}

func checkForString(siteAddress, port, protocol, stringToLookFor, pageToCheck string) (bool, string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{
		Timeout:   6 * time.Second,
		Transport: tr,
	}

	if len(pageToCheck) < 1 {
		pageToCheck = "/"
	}
	req, err := http.NewRequest("GET", (protocol + "://" + siteAddress + ":" + port + pageToCheck), nil)
	if err != nil {
		fmt.Println("\nERR_IN_FUNC: check_for_string: " + err.Error())
	}

	req.Host = siteAddress
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("\nERR_IN_FUNC: check_for_string: " + err.Error())
	}
	defer resp.Body.Close()
	dataInBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("\nERR_IN_FUNC: check_for_string: " + err.Error())
	}

	pageContent := string(dataInBytes)
	numberOfStringsPresent := strings.Index(pageContent, stringToLookFor)

	if numberOfStringsPresent == -1 {
		return false, strconv.Itoa(resp.StatusCode)
	} else {
		return true, strconv.Itoa(resp.StatusCode)
	}
}
