package cmd

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
		webPageInput := CheckWebPageInput{}
		webPageInput.siteAddress = site.SiteAddress
		webPageInput.port = site.Port
		webPageInput.protocol = site.Protocol
		webPageInput.stringToLookFor = site.String
		webPageInput.pageToCheck = site.PageToCheck
		webPageInput.yellowResponseTime = int64(site.YellowResponseTime)
		webPageInput.redResponseTime = int64(site.RedResponseTime)

		if len(webPageInput.pageToCheck) < 1 {
			webPageInput.pageToCheck = "/"
		}

		certDataVar := certDataOutputStruct{}
		certDataVarInput := certDataInputStruct{}
		certDataVarInput.port = webPageInput.port
		certDataVarInput.protocol = webPageInput.protocol
		certDataVarInput.siteAddress = webPageInput.siteAddress
		certDataVarInput.sslAmberDays = site.SslAlertTime
		if webPageInput.protocol == "http" {
			certDataVar.date = "N/A"
			certDataVar.status = "N/A"
			certDataVar.daysBeforeExpiration = "N/A"
		} else {
			var err error
			certDataVar, err = checkCertDate(certDataVarInput)
			if err != nil {
				if err != nil {
					certDataVar.date = "N/A"
					certDataVar.daysBeforeExpiration = "N/A"
					certDataVar.status = "N/A"
				}
			}
		}

		webPageOutput, err := checkWebPage(webPageInput)
		if err != nil {
			webPageOutput.httpStatusCode = "503"
			webPageOutput.responseTime = "N/A"
			webPageOutput.responseTimeStatusRed = true
			webPageOutput.responseTimeStatusRed = true
		}

		responseVar := finalResponseStruct{}
		responseVar.certEndDate.status = certDataVar.status
		responseVar.certEndDate.date = certDataVar.date
		responseVar.certEndDate.daysBeforeExpiration = certDataVar.daysBeforeExpiration

		responseVar.websiteAddress = webPageInput.siteAddress
		responseVar.httpStatus = webPageOutput.httpStatusCode
		responseVar.responseTime = webPageOutput.responseTime
		responseVar.stringPresent = webPageOutput.stringPresent

		idNumber = idNumber + 1
		idString := strconv.Itoa(idNumber)
		jsonOutput.ID = idString
		jsonOutput.SiteAddress = responseVar.websiteAddress
		jsonOutput.PageChecked = webPageInput.protocol + "://" + webPageInput.siteAddress + ":" + webPageInput.port + webPageInput.pageToCheck
		jsonOutput.HttpStatus = responseVar.httpStatus
		jsonOutput.ResponseTime = webPageOutput.responseTime
		jsonOutput.YellowResponseTime = webPageOutput.responseTimeStatusYellow
		jsonOutput.RedResponseTime = webPageOutput.responseTimeStatusRed
		jsonOutput.StringPresent = responseVar.stringPresent
		jsonOutput.CertStatus = responseVar.certEndDate.status
		jsonOutput.CertEndDate = responseVar.certEndDate.date
		jsonOutput.CertDaysBeforeEnd = responseVar.certEndDate.daysBeforeExpiration
		jsonOutput.Host = site.Host
		jsonOutput.Page = webPageInput.pageToCheck
		jsonOutput.StringChecked = webPageInput.stringToLookFor
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
		if len(site.SiteAddress) < 1 {
			continue
		}

		var webPageInput CheckWebPageInput

		webPageInput.siteAddress = site.SiteAddress
		webPageInput.port = site.Port
		webPageInput.protocol = site.Protocol
		webPageInput.stringToLookFor = site.String
		webPageInput.pageToCheck = site.PageToCheck
		webPageInput.yellowResponseTime = int64(site.YellowResponseTime)
		webPageInput.redResponseTime = int64(site.RedResponseTime)

		if len(webPageInput.pageToCheck) < 1 {
			webPageInput.pageToCheck = "/"
		}

		certDataVarInput := certDataInputStruct{}
		certDataVarInput.port = webPageInput.port
		certDataVarInput.protocol = webPageInput.protocol
		certDataVarInput.siteAddress = webPageInput.siteAddress
		certDataVarInput.sslAmberDays = site.SslAlertTime
		checkCertDateVar, err := checkCertDate(certDataVarInput)
		if err != nil {
			checkCertDateVar.date = "N/A"
			checkCertDateVar.daysBeforeExpiration = "N/A"
			checkCertDateVar.status = "N/A"
		}

		webPageOutput, err := checkWebPage(webPageInput)
		if err != nil {
			webPageOutput.httpStatusCode = "503"
			webPageOutput.responseTime = "N/A"
			webPageOutput.responseTimeStatusRed = true
			webPageOutput.responseTimeStatusRed = true
		}

		responseVar := finalResponseStruct{}
		responseVar.certEndDate.date = checkCertDateVar.date

		if checkCertDateVar.status == "yellow" {
			responseVar.certEndDate.date = yellowColor + responseVar.certEndDate.date + resetStyle
		} else if checkCertDateVar.status == "red" {
			responseVar.certEndDate.date = redColor + responseVar.certEndDate.date + resetStyle
		}

		responseVar.websiteAddress = webPageInput.siteAddress
		responseVar.httpStatus = webPageOutput.httpStatusCode
		if webPageOutput.responseTimeStatusYellow {
			webPageOutput.responseTime = yellowColor + webPageOutput.responseTime + resetStyle
		}
		if webPageOutput.responseTimeStatusRed {
			webPageOutput.responseTime = redColor + webPageOutput.responseTime + resetStyle
		}
		websitePageChecked := webPageInput.protocol + "://" + webPageInput.siteAddress + ":" + webPageInput.port + webPageInput.pageToCheck

		var stringPresent string
		if webPageOutput.stringPresent {
			stringPresent = " (present)"
		} else {
			stringPresent = redColor + " (missing)" + resetStyle
		}
		stringCheck := webPageInput.stringToLookFor + stringPresent

		idNumber = idNumber + 1
		idString := strconv.Itoa(idNumber)
		t.AddRow(idString, site.Host, websitePageChecked, responseVar.certEndDate.date, responseVar.httpStatus, webPageOutput.responseTime, stringCheck)
		if err := bar.Add(1); err != nil {
			log.Fatal("Can't spawn the progress bar: " + err.Error())
		}
	}
	t.Render()
}

type certDataInputStruct struct {
	siteAddress  string
	port         string
	protocol     string
	sslAmberDays int
}

type certDataOutputStruct struct {
	status               string
	daysBeforeExpiration string
	date                 string
}

func checkCertDate(inputStruct certDataInputStruct) (certDataOutputStruct, error) {
	if inputStruct.siteAddress == "" {
		log.Fatal("Site address was not specified!")
	}
	certDataOutput := certDataOutputStruct{}
	if inputStruct.protocol != "https" {
		certDataOutput.date = "N/A"
		certDataOutput.status = "N/A"
		certDataOutput.daysBeforeExpiration = "N/A"
		return certDataOutput, nil
	}

	timeout := 5 * time.Second
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", inputStruct.siteAddress+":"+inputStruct.port, conf)
	if err != nil {
		return certDataOutputStruct{}, err
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates

	var certStatus string
	certDate := certs[0].NotAfter.Format("02/01/2006")
	daysUntilExp := (time.Since(certs[0].NotAfter).Hours() / float64(inputStruct.sslAmberDays)) * -1
	daysUntilExpStr := fmt.Sprintf("%.0f", daysUntilExp)

	emberCertStatus := time.Now().AddDate(0, 0, +inputStruct.sslAmberDays)
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

	certDataOutput.status = certStatus
	certDataOutput.date = certDate
	certDataOutput.daysBeforeExpiration = daysUntilExpStr

	return certDataOutput, nil
}

type CheckWebPageInput struct {
	siteAddress        string
	port               string
	protocol           string
	stringToLookFor    string
	pageToCheck        string
	yellowResponseTime int64
	redResponseTime    int64
}

type CheckWebPageOutput struct {
	responseTime             string
	responseTimeStatusRed    bool
	responseTimeStatusYellow bool
	stringPresent            bool
	httpStatusCode           string
}

func checkWebPage(webPageInput CheckWebPageInput) (CheckWebPageOutput, error) {
	// fmt.Println(webPageInput)
	startTime := time.Now()
	webPageOutput := CheckWebPageOutput{}

	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{
		Timeout:   20 * time.Second,
		Transport: httpTransport,
	}

	if len(webPageInput.pageToCheck) < 1 {
		webPageInput.pageToCheck = "/"
	}

	req, err := http.NewRequest("GET", (webPageInput.protocol + "://" + webPageInput.siteAddress + ":" + webPageInput.port + webPageInput.pageToCheck), nil)
	if err != nil {
		return CheckWebPageOutput{}, errors.New("could not perform the request (line 471): " + err.Error())
	}

	req.Host = webPageInput.siteAddress
	resp, err := httpClient.Do(req)
	if err != nil {
		return CheckWebPageOutput{}, err
	}

	dataInBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return CheckWebPageOutput{}, err
	}

	pageContent := string(dataInBytes)
	numberOfStringsPresent := strings.Index(pageContent, webPageInput.stringToLookFor)

	webPageOutput.stringPresent = true
	if numberOfStringsPresent == -1 {
		webPageOutput.stringPresent = false
	}

	webPageOutput.httpStatusCode = strconv.Itoa(resp.StatusCode)
	defer resp.Body.Close()

	rTime := time.Since(startTime).Milliseconds()
	webPageOutput.responseTime = strconv.FormatInt(rTime, 10)

	if rTime > int64(webPageInput.yellowResponseTime) {
		webPageOutput.responseTimeStatusYellow = true
	}
	if rTime > int64(webPageInput.redResponseTime) {
		webPageOutput.responseTimeStatusRed = true
	}

	return webPageOutput, nil
}
