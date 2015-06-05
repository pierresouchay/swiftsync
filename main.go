package main

// Swift Sync
//
// A simple and performant tool to synchronize Openstack Swift with your local
// File systems
// by Pierre SOUCHAY (twitter: @vizionr), 2015
import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Keystone Serializarion Types

type ResultToken struct {
	Id      string
	expires string
}

type ResultUser struct {
	Username string
	Id       string
}

type ResultCatalogEndpoint struct {
	PublicURL   string
	InternalURL string
	Region      string
}

type ResultCatalogEntry struct {
	Type      string
	EndPoints []ResultCatalogEndpoint
}

type ResultAccess struct {
	Token          ResultToken
	User           ResultUser
	ServiceCatalog []ResultCatalogEntry
}

type ResultTokenResponse struct {
	Access ResultAccess
}

type PasswdCredsType struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenType struct {
	Id string `json:"id"`
}

type AuthType struct {
	PasswordCredentials PasswdCredsType `json:"passwordCredentials,omitempty"`
	//Token               *TokenType      `json:"token,omitempty"`
	TenantId   string `json:"tenantId,omitempty"`
	TenantName string `json:"tenantName,omitempty"`
}

type KeystoneAuth struct {
	Auth AuthType `json:"auth"`
}

type KeystoneConfiguration struct {
	Url          string       `json:"url"`
	Post         KeystoneAuth `json:"post"`
	Region       string       `json:"region"`
	UsePublicURL bool         `json:"usePublicURL"`
}

// Configuration types

type ConfigurationTarget struct {
	Containers            []string `json:"containers"`
	Directory             string   `json:"directory"`
	Ignore                []string `json:"ignore"`
	StrictMd5             bool     `json:"strictMd5"`
	OverwriteLocalChanges bool     `json:"overwriteLocalChanges"`
}

type Configuration struct {
	Keystone KeystoneConfiguration `json:"keystone"`
	Target   ConfigurationTarget   `json:"target"`
}

type DownloadStrategy int

const (
	Download DownloadStrategy = 1 << iota
	SkipErr  DownloadStrategy = 2
	Skip     DownloadStrategy = 3
)

type ContainerInfo struct {
	Count int64
	Bytes int64
	Name  string
}

type ObjectInfo struct {
	Name          string
	Hash          string
	Last_modified string
	Bytes         int64
	Content_type  string
}

func (this *ObjectInfo) GetLastModifiedAsSec() (time.Time, error) {
	const dateFormat = "2006-01-02T15:04:05.999999999"
	t, err := time.Parse(dateFormat, this.Last_modified);
	if err!=nil {
		return t, err
	}
	return t.Truncate(time.Second), err
}

type DownloadInfo struct {
	Download DownloadStrategy
	Object   ObjectInfo
	Url      string
	File     string
	localMd5 string
}

type ProcessingType int

const (
	Folder ProcessingType = 1 << iota
	File   ProcessingType = 2
)

type CurrentProcess struct {
	Type    ProcessingType
	message string
}



// List a container and returns its listing
func listContainer(token string, urlStr string, containerName string, marker string) ([]ObjectInfo, error) {
	fullUrl := urlStr
	if !strings.HasSuffix(urlStr, "/") {
		fullUrl += "/"
	}
    daUrl, err := url.Parse(fullUrl)
    if err != nil {
    	return nil, err
    }
    
	daUrl.Path+= containerName
	daUrl.RawQuery=fmt.Sprintf("limit=%d", MAX_OBJECTS_PER_LISTING)
	if "" != "marker" {
		daUrl.RawQuery += "&marker=" + url.QueryEscape(marker)
	}

	req, err := http.NewRequest("GET", daUrl.String(), nil)
	if err != nil {
		panic(err)
	}

	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)

	//if (resp.

	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, err
	}

	// read json http response
	jsonDataFromHttp, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var listing []ObjectInfo
	err = json.Unmarshal(jsonDataFromHttp, &listing)

	return listing, err
}

func computeHMAC(key []byte, message string) string {
	mac := hmac.New(sha1.New, key)
	mySlice := []byte(message)
	mac.Write(mySlice)
	return hex.EncodeToString(mac.Sum(nil))
}

func generateTempUrlQuery(key []byte, method string, path string, expires int64) string {
	message := fmt.Sprintf("%s\n%d\n%s", method, expires, path)
	temp_url_sig := computeHMAC(key, message)
	return fmt.Sprintf("temp_url_sig=%s&temp_url_expires=%d", temp_url_sig, expires)
}

func createTempUrl(key []byte, basePath string, containerName string, path string) (string, string) {
	expires := time.Now().Unix() + 18000
	absPath := basePath + "/" + containerName + "/" + path
	return absPath, generateTempUrlQuery(key, "GET", absPath, expires)
}

func ComputeMd5(filePath string) ([]byte, error) {
	var result []byte
	file, err := os.Open(filePath)
	if err != nil {
		return result, err
	}

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		file.Close()
		return result, err
	}
	file.Close()

	return hash.Sum(result), nil
}

const CACHE_DIRECTORY = ".swiftsync/.cache/";

var conf Configuration

func writeCacheEntry(containerName string, object ObjectInfo, remoteMd5 string) error {
	cacheFileName:= conf.Target.Directory + CACHE_DIRECTORY +containerName + "/" + object.Name
	directory := filepath.Dir(cacheFileName)
	os.MkdirAll(directory, 0777)
	
	err:= ioutil.WriteFile( cacheFileName, []byte(remoteMd5), 0666)
	if err!=nil {
		return err
	}
	t, err:= object.GetLastModifiedAsSec()
	if err != nil{
		return err	
	}
	os.Chtimes(cacheFileName, t, t)
	return err	
}

func readMd5CacheEntry(containerName string, object ObjectInfo, localLastModified time.Time) string {
    cacheFileName:= conf.Target.Directory + CACHE_DIRECTORY +containerName + "/" + object.Name
	fileInfo, err := os.Stat(cacheFileName)
	
	if err != nil {
		//fmt.Printf("\n*** Cannot load cache file : %s ***\n", cacheFileName)
		return ""
	}
	t, err := object.GetLastModifiedAsSec()
	if err != nil {
		fmt.Printf("\n*** Cannot parse date %s of object : %s ***\n", object.Last_modified, object.Name, err)
		panic(err)
	}
	if localLastModified.Unix() != t.Unix() {
		//fmt.Printf("\n*** ERR1: %d VS %d \n", localLastModified.Unix(), t.Unix())
		return ""
	}
	modTime := fileInfo.ModTime();
	if (modTime.Unix() != localLastModified.Unix()){
		//fmt.Printf("\n*** ERR1: %d VS %d \n", modTime.Unix(), localLastModified.Unix())
		return ""
	}
	file, err := os.Open(cacheFileName)
	if err != nil {
		panic(err)
		return ""
	}
	data, err := ioutil.ReadAll(file)
	if err!=nil {
		file.Close()
		return ""
	}
	file.Close()
    md5Data:= string(data);
	//fmt.Println("\n*** Read MD5: "+md5Data)
	return md5Data
}

//
// Returns whether we have to download the file
//
func shouldDownloadFile(containerName string, object ObjectInfo, compareWithFile string) (DownloadStrategy, string) {
	if strings.HasSuffix(object.Name, "/") || object.Content_type == "inodes/directory" || -1 != strings.Index(object.Name, "/.part-") {
		return Skip, ""
	}
	fileInfo, err := os.Stat(compareWithFile)

	if err != nil {
		return Download, ""
	}
	t, err := object.GetLastModifiedAsSec()
	if err != nil {
		fmt.Printf("\n*** Cannot parse date %s of object : %s ***", object.Last_modified, object.Name, err)
		panic(err)
	}
	modTime := fileInfo.ModTime();
	localSize := fileInfo.Size()
	
	if localSize != object.Bytes {
		if localSize > 0 && !conf.Target.OverwriteLocalChanges && modTime.After(t) {
			fmt.Fprintf(os.Stderr, "\r*** File %s is more recent %s than the file from server (%s), ignoring ***\n", compareWithFile, fileInfo.ModTime(), t)
			return SkipErr, ""
		}
		if object.Bytes != 0 {
			return Download, ""	
		} else {
			return Download, readMd5CacheEntry(containerName, object, modTime)
		}
	}
	localMd5:= ""
	if conf.Target.StrictMd5 || modTime.Before(t) || object.Bytes == 0 {
		// We check the md5
		md5sum, err := ComputeMd5(compareWithFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\r*** Hash computation error for %s %s\n", compareWithFile, err.Error())
			// We cannot compute MD5, file deleted ? Download !
			return Download, ""
		}
	    localMd5 = hex.EncodeToString(md5sum)
		if object.Hash == localMd5{
			return Skip, localMd5
		} else {
			return Download, localMd5
		}
	}
	// Since Swift API sucks, we have to retry download
	if object.Bytes == 0{
		return Download, localMd5	
	}
	return Skip, localMd5
}

// checkClose is used to check the return from Close in a defer
// statement.
func checkClose(c io.Closer, err *error) {
	cerr := c.Close()
	if *err == nil {
		*err = cerr
	}
}

var partialDownloadDate = time.Date(1979, time.November, 6, 18, 30, 0, 0, time.FixedZone("UTC", 0))

func saveFile(containerName string, object ObjectInfo, url string, saveAs string, localMd5 string) (DownloadStrategy, error) {	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR - Cannot initialize HTTP Client for downloading file: %s\n", err.Error())
		return SkipErr, err
	}
    localETag := ""
	
	if localMd5 != "" {
		if strings.HasPrefix(localMd5, "\""){
			localETag = localMd5
		} else {
			localETag = fmt.Sprintf("\"%s\"", localMd5);
		}
		req.Header.Set("If-None-Match", localETag)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return SkipErr, err
	}

	if resp.StatusCode == 304 || (localETag!="" && localETag == resp.Header.Get("ETag")) {
		// Not modified, we don't download again
		//fmt.Println("\nSKIPPED If-None-Match: "+localMd5+", not downloaded for "+url);
		resp.Body.Close()
		return Skip, nil
	} else if resp.StatusCode != 200 {
		resp.Body.Close()
		//fmt.Println("\nERROR: "+localMd5+", not downloaded for "+url);
		return Skip, fmt.Errorf("Cannot download file %s, HTTP %d: %s", url, resp.StatusCode, resp.Status)
	}
	
	directory := filepath.Dir(saveAs)
	os.MkdirAll(directory, 0777)
	out, err := os.Create(saveAs)
	if err != nil {
		resp.Body.Close()
		if out != nil {
			out.Close()
		}
		return SkipErr, err
	}
	// We setup its date to 1970, since we want to recover the file if download does not finish properly
	t, errTime := object.GetLastModifiedAsSec()
	if errTime == nil {
		os.Chtimes(saveAs, t, t)
	} else {
		os.Chtimes(saveAs, partialDownloadDate, partialDownloadDate)
	}
	io.Copy(out, resp.Body)
	resp.Body.Close()
	out.Close()
	if err != nil {
		// We have an error downloading the file, we setup time to be my birthday, so it will be re-downloaded again :-)
		os.Chtimes(saveAs, partialDownloadDate, partialDownloadDate)
		return SkipErr, err
	}

	if errTime == nil {
		os.Chtimes(saveAs, t, t)
	}
    manifest:= resp.Header.Get("X-Object-Manifest")
    if "" != manifest {
    	//fmt.Printf("\n*** Detected Large Object %s *** md5:=%s VS %s -- %s\n", url, localETag, resp.Header.Get("ETag"), localMd5)
        errCache:= writeCacheEntry(containerName, object, resp.Header.Get("ETag"))
        if errCache != nil {
        	fmt.Fprintf(os.Stderr, "\n*** Failed to write Cache entry for %s/%s: %s ***\n", containerName, object.Name, errCache.Error())
        } else {
        	//fmt.Printf("\n*** Cache entry written for %s/%s ***\n", containerName, object.Name)
        }
    }
    	
	return Download, nil
}

func authToKeystone(keystoneUrl string, keystoneCredentials KeystoneAuth, optionalRegion string) (*url.URL, string, error) {
	jsonPostData, err := json.Marshal(keystoneCredentials)
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequest("POST", keystoneUrl, bytes.NewBuffer(jsonPostData))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)

	//if (resp.

	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, "", err
	}

	httpCode := resp.StatusCode
	if httpCode != 200 {
		resp.Body.Close()
		if httpCode == 401 {
			return nil, "", fmt.Errorf("Wrong credentials (%d): %s", httpCode, resp.Status)
		}
		return nil, "", fmt.Errorf("Keystone auth failed with error code %d: %s", httpCode, resp.Status)
	}

	// read json http response
	jsonDataFromHttp, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		panic(err)
	}

	var listing ResultTokenResponse
	err = json.Unmarshal(jsonDataFromHttp, &listing)
	if err != nil {
		panic(err)
	}
	defer checkClose((resp.Body), &err)
	var objectStoreEndPoints *ResultCatalogEntry = nil
	for _, endP := range listing.Access.ServiceCatalog {
		objectStoreEndPoints = &endP
		if endP.Type == "object-store" {
			for _, endPointInformation := range endP.EndPoints {
				if optionalRegion == "" || (optionalRegion) == endPointInformation.Region {
					urlToParse := endPointInformation.PublicURL
					if !conf.Keystone.UsePublicURL {
						urlToParse = endPointInformation.InternalURL
					}
					theUrl, err := url.Parse(urlToParse)
					return theUrl, listing.Access.Token.Id, err
				}
			}
		}
	}
	if objectStoreEndPoints != nil {
		if optionalRegion != "" {
			return nil, "", fmt.Errorf("Region %s could not be found in endpoints %s", optionalRegion, *objectStoreEndPoints)
		} else {
			return nil, "", fmt.Errorf("objet-store has been found, but no endpoint seems configured: %s", *objectStoreEndPoints)
		}
	}
	return nil, "", fmt.Errorf("Could not find Object store endpoint in %s", listing)
}

func downloadAndNotify(containerName string, info *DownloadInfo) (DownloadStrategy, error) {
	return saveFile(containerName, info.Object, info.Url, info.File, info.localMd5)
}

func readConfiguration(filestr string, configuration *Configuration) error {
	var file io.Reader
	var err error
	if filestr != "-" { // Works with stdin
		file, err = os.Open(filestr)
		if err != nil {
			return err
		}
	} else {
		file = os.Stdin
	}

	decoder := json.NewDecoder(file)
	err = decoder.Decode(configuration)
	if err != nil {
		return err
	}
	return nil
}

func getEnvOrDefault(envName string, defaultValue string) string {
	val := os.Getenv(envName)
	if val == "" {
		return defaultValue
	}
	return val
}

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage: %s [configuration_file.json]:\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(127)
}


func drainDownload(processing *(chan *CurrentProcess), currentDownloads *(chan *DownloadInfo), numFiles *int, filesErrors *int, filesDownloaded *int, filesSkippedErr *int, filesSkipped *int, bytesDl *int64, c *ContainerInfo) {
	msg := <-(*currentDownloads)
	(*numFiles)--
    dlRet := msg.Download
	if msg.Download == Download {
		fName := msg.File
		strLen := len(fName)
		if strLen > 64 {
			fName = fName[0:30] + "\u2026" + fName[strLen-32:strLen]
		}
		(*processing) <- &CurrentProcess{File, fmt.Sprintf("%12s %12d %12d %12d %12d %12d %12d %12d %-64s", "Downloading", *filesDownloaded, *filesSkipped, *filesSkippedErr, *filesErrors, (*c).Count, (*c).Bytes, *bytesDl, fName)}
		var err error = nil
 		dlRet, err = downloadAndNotify((*c).Name, msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n*** Error downloading %s: %s ***\n", msg.File, err.Error())
			(*filesErrors)++
		}
	}
	if dlRet == SkipErr {
		(*filesSkippedErr)++
	} else if dlRet == Skip {
		(*filesSkipped)++
	} else if dlRet == Download {
		(*bytesDl) += msg.Object.Bytes
		(*filesDownloaded)++
	}
}

func generateRandomStringForTempUrl() string {
	digits := []rune("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	rand.Seed(time.Now().UTC().UnixNano())
	b := make([]rune, 64)
	for i := range b {
		b[i] = digits[rand.Intn(len(digits))]
	}
	return string(b)
}

const MAX_OBJECTS_PER_LISTING = 10000

const MAX_LISTINGS_AT_ONCE = 16

const MAX_DOWNLOADS_AT_ONCE_PER_CONTAINER = 16

func main() {
	token := ""

	conf = Configuration{

		Keystone: KeystoneConfiguration{
			Url: "https://identity.fr1.cloudwatt.com/v2.0/tokens",
			Post: KeystoneAuth{
				Auth: AuthType{
					PasswordCredentials: PasswdCredsType{
						Username: getEnvOrDefault("OS_USERNAME", "me@example.com"),
						Password: getEnvOrDefault("OS_PASSWORD", "password is missing")},
					TenantId:   getEnvOrDefault("OS_TENANT_ID", ""),
					TenantName: getEnvOrDefault("OS_TENANT_NAME", ""),
				}},
			UsePublicURL: true,
			Region:       getEnvOrDefault(os.Getenv("OS_REGION_NAME"), "")},
		Target: ConfigurationTarget{Containers: []string{".*"},
			Directory:             "sync",
			Ignore:                []string{},
			StrictMd5:             false,
			OverwriteLocalChanges: false}}

	{
		//strictMd5:= conf.Target.StrictMd5
		//flag.BoolVar(&(conf.Target.StrictMd5), "md5", false, "Always compare local MD5 with remote MD5 (slower)")
		//flag.BoolVar(&(conf.Target.OverwriteLocalChanges), "overwrite", false, "Overwrite local files when the files are different from Swift")
		//flag.StringVar(&(conf.Target.Directory), "directory", conf.Target.Directory, "Directory where to upload files")
		flag.Parse()
		args := flag.Args()
		if len(args) > 0 {
			if len(args) > 1 {
				fmt.Fprintf(os.Stderr, "Error - Only one or no configuration file can be provided, but several were given: '%s'\n", args)
				(Usage)()
				os.Exit(126)
			} else {
				configFile := flag.Arg(0)
				err := readConfiguration(configFile, &conf)
				// Lets init the configuration
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error - Failed to read configuration file '%s': '%s'\n", configFile, err.Error())
					os.Exit(1)
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "Generating an example configuration using environment\nValues are read from your environment, so it may be time to load your openstack.rc file\nSave the following content into a file, a start again the program with the file as argument.\n--------\n")
			if conf.Keystone.Post.Auth.TenantId == "" && conf.Keystone.Post.Auth.TenantName == "" {
				conf.Keystone.Post.Auth.TenantName = "tenantName, or you can use tenantId property instead"
			}
			jsonData, err := json.MarshalIndent(conf, "", "    ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error - Failed to serialize JSON Data '%s': '%s'\n", conf, err.Error())
				os.Exit(666)
			}
			fmt.Println(string(jsonData))
			os.Exit(0)
		}
	}

	{
		// Check URL format
		if !strings.HasSuffix(conf.Keystone.Url, "/tokens") {
			if strings.HasSuffix(conf.Keystone.Url, "/v2.0") {
				conf.Keystone.Url += "/tokens"
			} else if strings.HasSuffix(conf.Keystone.Url, "/v2.0/") {
				conf.Keystone.Url += "tokens"
			} else {
				// Do not try magic, use it
			}
		}

		if !strings.HasSuffix(conf.Target.Directory, "/") {
			if conf.Target.Directory == "" {
				conf.Target.Directory += "."
			}
			conf.Target.Directory += "/"
		}
	}

	ContainersRegexps := make([]regexp.Regexp, len(conf.Target.Containers), len(conf.Target.Containers))
	for idx, val := range conf.Target.Containers {
		directoryRegexp, err := regexp.Compile(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error - Failed to compile regexp '%s' from Containers property array '%s': '%s'\n", val, conf.Target.Containers, err.Error())
			os.Exit(125)
		}
		ContainersRegexps[idx] = *directoryRegexp
	}

	IgnoreRegexps := make([]regexp.Regexp, len(conf.Target.Ignore), len(conf.Target.Ignore))
	for idx, val := range conf.Target.Ignore {
		ignoreRegexp, err := regexp.Compile(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error - Failed to compile regexp '%s' from Ignore property array '%s': '%s'\n", val, conf.Target.Ignore, err.Error())
			os.Exit(125)
		}
		IgnoreRegexps[idx] = *ignoreRegexp
	}
	baseUrl, token, err := authToKeystone(conf.Keystone.Url, conf.Keystone.Post, conf.Keystone.Region)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR - Could not get token: %s\n", err.Error())
		os.Exit(2)
	}

	const MAX_CONTAINERS_PER_LISTING = 100

	req, err := http.NewRequest("GET", fmt.Sprintf("%s?limit=%d", baseUrl.String(), MAX_CONTAINERS_PER_LISTING), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR - Cannot initialize HTTP Client: %s\n", err.Error())
		os.Exit(3)
	}

	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR - Cannot list containers: %s\n", err.Error())
		os.Exit(3)
	}

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "ERROR - Failed to connect to Swift, HTTP Code: %d, Message: %s", resp.StatusCode, resp.Status)
		os.Exit(4)
	}

	var key []byte
	{
		tempUrlKey := resp.Header.Get("X-Account-Meta-Temp-Url-Key")
		if tempUrlKey == "" || len(tempUrlKey) < 3 {
			tempUrlKey = resp.Header.Get("X-Account-Meta-Temp-Url-Key-2")
		}

		if tempUrlKey == "" || len(tempUrlKey) < 3 {
			// No temp URL key has been setup, let's try to create one
			tempUrlKey = generateRandomStringForTempUrl()
			req, err := http.NewRequest("POST", baseUrl.String(), nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR - Cannot initialize HTTP Client: %s\n", err.Error())
				os.Exit(3)
			}
			fmt.Println("INFO: X-Account-Meta-Temp-Url-Key(-2) were not found, initializing a new one...")
			req.Header.Set("X-Auth-Token", token)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("X-Account-Meta-Temp-Url-Key", tempUrlKey)

			client := &http.Client{}
			resp, err := client.Do(req)

			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR - Cannot upload new X-Account-Meta-Temp-Url-Key: %s\n", err.Error())
				os.Exit(3)
			}

			if resp.StatusCode > 299 {
				fmt.Fprintf(os.Stderr, "ERROR - Failed to connect to Swift to upload new X-Account-Meta-Temp-Url-Key, HTTP Code: %d, Message: %s", resp.StatusCode, resp.Status)
				os.Exit(4)
			}

			resp.Body.Close()

		}
		key = []byte(tempUrlKey)
	}
	// read json http response
	jsonDataFromHttp, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR - Could not read listing from Swift: %s", err.Error())
		os.Exit(5)
	}

	var containers []ContainerInfo

	err = json.Unmarshal(jsonDataFromHttp, &containers)

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR - Could not parse JSON listing from Swift: %s", err.Error())
		os.Exit(6)
	}

	processing := make(chan *CurrentProcess)
	var waitingTasks = 0
	fmt.Println(" Sync Status   Downloaded      in Sync      Skipped       Errors  Total Files        Bytes     DL Bytes Name")
	hasErrors := false
	hasMoreContainers := true

	for hasMoreContainers {
		for _, container := range containers {
			for _, regContainer := range ContainersRegexps {
				if regContainer.MatchString(container.Name) {
					waitingTasks++

					if container.Count == 0 {
						go func(c ContainerInfo) {
							// Optimization for empty containers
							processing <- &CurrentProcess{Folder, fmt.Sprintf("%12s %12d %12d %12d %12d %12d %12d %12d %-64s", "OK", 0, 0, 0, 0, c.Count, c.Bytes, 0, c.Name)}
						}(container)
					} else {
						go func(c ContainerInfo) {
							status := "OK"
							filesErrors := 0
							filesDownloaded := 0
							filesSkipped := 0
							filesSkippedErr := 0
							bytesDl := int64(0)
							numFiles := 0
							currentDownloads := make(chan *DownloadInfo)
							listing, errListing := listContainer(token, baseUrl.String(), c.Name, "")
							if errListing != nil {
								status = "List failed"
								hasErrors = true
							} else {
								hasMore := true
								for hasMore {

									for _, obj := range listing {
										numFiles++
										go func(obj ObjectInfo, c ContainerInfo) {
											ignoreFile := false
											for _, ignore := range IgnoreRegexps {
												if ignore.MatchString(obj.Name) {
													fmt.Println(obj.Name)
													ignoreFile = true
													break
												}
											}
											download := Skip
											fileName := conf.Target.Directory + c.Name + "/" + obj.Name
											localMd5:=""
											if !ignoreFile {
												download, localMd5 = shouldDownloadFile(c.Name, obj, fileName)
											}
											info := &DownloadInfo{download, obj, "", fileName, localMd5}
											switch download {
											case Download:
												absPath, query := createTempUrl(key, baseUrl.Path, c.Name, obj.Name)
												toDl, err := url.Parse(baseUrl.String())
												toDl.Path = absPath
												toDl.RawQuery = query
												info.Url = toDl.String()
												if err != nil {
													info.Download = SkipErr
												}
											case Skip:
												//currentDownloads <- fmt.Sprintf("Skip ", obj)
											case SkipErr:
												//currentDownloads <- fmt.Sprintf("SkipErr ", obj)
											}
											currentDownloads <- info

										}(obj, c)
										// Max 8 downloads in //
										for numFiles > MAX_DOWNLOADS_AT_ONCE_PER_CONTAINER {
											drainDownload(&processing, &currentDownloads, &numFiles, &filesErrors, &filesDownloaded, &filesSkippedErr, &filesSkipped, &bytesDl, &c)
										}
									} //

									for numFiles > 0 {
										drainDownload(&processing, &currentDownloads, &numFiles, &filesErrors, &filesDownloaded, &filesSkippedErr, &filesSkipped, &bytesDl, &c)
									}
									if len(listing) == MAX_OBJECTS_PER_LISTING {
										listing, errListing = listContainer(token, baseUrl.String(), c.Name, listing[len(listing)-1].Name)
										if errListing != nil {
											status = "List failed"
											hasMore = false
											hasErrors = true
											break
										} else {
											hasMore = true
										}
									} else {
										hasMore = false
									}
								}
							}

							if filesErrors > 0 {
								status = "Errors"
								hasErrors = true
							} else if filesSkippedErr > 0 {
								status = "Local Diff"
							}
							processing <- &CurrentProcess{Folder, fmt.Sprintf("%12s %12d %12d %12d %12d %12d %12d %12d %-64s", status, filesDownloaded, filesSkipped, filesSkippedErr, filesErrors, c.Count, c.Bytes, bytesDl, c.Name)}

						}(container)
					}
					break
				}
			}
			// MAX
			for waitingTasks > MAX_LISTINGS_AT_ONCE {
				msg := <-processing
				if msg.Type == Folder {
					waitingTasks--
					fmt.Printf("\r%s\n", msg.message)
				} else {
					fmt.Printf("\r%s", msg.message)
				}
			}
		}
		for waitingTasks > 0 {
			msg := <-processing
			if msg.Type == Folder {
				waitingTasks--
				fmt.Printf("\r%s\n", msg.message)
			} else {
				fmt.Printf("\r%s", msg.message)
			}
		}
		if len(containers) == MAX_CONTAINERS_PER_LISTING {
			// We have to continue the listing
			containerMarker := containers[len(containers)-1].Name
			req, err = http.NewRequest("GET", fmt.Sprintf("%s?limit=%d&marker=%s", baseUrl.String(), MAX_CONTAINERS_PER_LISTING, url.QueryEscape(containerMarker)), nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR - Cannot initialize HTTP Client: %s\n", err.Error())
				os.Exit(3)
			}

			req.Header.Set("X-Auth-Token", token)
			req.Header.Set("Accept", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)

			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR - Cannot list containers: %s\n", err.Error())
				os.Exit(3)
			}

			if resp.StatusCode != 200 {
				fmt.Fprintf(os.Stderr, "ERROR - Failed to connect to Swift, HTTP Code: %d, Message: %s", resp.StatusCode, resp.Status)
				os.Exit(4)
			}
			// read json http response
			jsonDataFromHttp, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()

			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR - Could not read listing from Swift: %s", err.Error())
				os.Exit(5)
			}

			err = json.Unmarshal(jsonDataFromHttp, &containers)

			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR - Could not parse JSON listing from Swift: %s", err.Error())
				os.Exit(6)
			}
			hasMoreContainers = true

		} else {
			hasMoreContainers = false
		}

	}
	if hasErrors {
		os.Exit(16)
	}
}
