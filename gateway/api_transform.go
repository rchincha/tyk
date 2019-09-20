package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/TykTechnologies/tyk/config"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-retryablehttp"
	"gopkg.in/yaml.v2"
	"time"
)

//nolint
var (
	TykHTTPPort                  = "4430"
	TykJWTAPIKeyEndpoint         = "/tyk/keys/"
	TykBundlesFolder             = config.Global().MiddlewarePath + "/" + TykBundles
	TykRoot                      = "/data/tyk-gateway/"
	TykCACert                    = "/certs/cacerts.crt"
	TykServerCrt                 = "/certs/server.crt"
	TykServerKey                 = "/certs/server.key"
	TykUpstreamPem               = "/certs/upstream.pem"
	SystemConfigFilePath         = "/data/config/systemconfig.yaml"
	TykMiddlewareRoot            = "/data/tyk-gateway/middleware/"
	TykMiddlewareSrcFile         = TykRoot + TykMiddlewareFile
	TykMiddlewareManifestSrcFile = TykRoot + TykManifest
	JWTDefinitionsSpec           = TykRoot + "/jwt_definition.json"
	TykConfFilePath              = TykRoot + "/tyk.conf"
	JWTApiKeySpec                = TykRoot + "/token_jwt.json"
	APITemplateOpenSpec          = TykRoot + "/api_template_open.json"
	APITemplateJWTSpec           = TykRoot + "/api_template_jwt.json"
	TykMiddlewareBundleNameHash  = "c343271e0935000c0ea41f8d9822015c"
	TykBundles                   = "bundles"
	TykMiddlewareBundleName      = "bundle.zip"
	TykMiddlewareFile            = "middleware.py"
	TykManifest                  = "manifest.json"
)

// URLRewrite struct to store URLRewrite
type URLRewrites struct {
	Path         string   `json:"path"`
	Method       string   `json:"method"`
	MatchPattern string   `json:"match_pattern"`
	RewriteTo    string   `json:"rewrite_to"`
	Triggers     []string `json:"triggers"`
	MatchRegexp  string   `json:"match_regexp"`
}

// Middleware config data
type PythonMiddlewareConfigData struct {
	InjectK8sAuthHeader bool   `json:"inject_k8s_auth_header"`
	InjectJwtHeader     bool   `json:"inject_jwt_headers"`
	K8sAuthTokenPath    string `json:"k8s_auth_token_path"`
}

// Golang Middleware config data
type GolangMiddlewareConfigData struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// APIDefinition to store api definition
type APIDefinition struct {
	APIID                      string                     `json:"api_id"`
	Name                       string                     `json:"name"`
	Slug                       string                     `json:"slug"`
	Platforms                  []string                   `json:"platforms"`
	ListenPath                 string                     `json:"listen_path"`
	TargetURL                  string                     `json:"target_url"`
	AuthType                   string                     `json:"authtype"`
	EnablePythonMiddleware     bool                       `json:"enable_python_middleware"`
	EnableGolangMiddleware     bool                       `json:"enable_golang_middleware"`
	EnableMTLS                 bool                       `json:"enable_mtls"`
	UpdateTargetHost           bool                       `json:"update_target_host"`
	PythonMiddlewareConfigData PythonMiddlewareConfigData `json:"python_middleware_config_data"`
	GolangMiddlewareConfigData GolangMiddlewareConfigData `json:"golang_middleware_config_data"`
	URLRewrites                []URLRewrites              `json:"url_rewrites"`
}

// JWTDefinitions to store JWTDefinition
type JWTDefinition struct {
	Name             string `json:"name"`
	JWTPublicKeyPath string `json:"jwt_public_key_path"`
	JWTAPIKeyPath    string `json:"jwt_api_key_path"`
	JWTMinKeyLength  int    `json:"jwt_min_key_length"`
}

// APIDefinitions to store APIDefinitions
type APIDefinitions struct {
	APIDefinitions []APIDefinition `json:"api_definitions"`
}

// JWTDefinitions to store JWTDefinitions
type JWTDefinitions struct {
	JWTDefinitions []JWTDefinition `json:"jwt_definitions"`
}

// TokenAccessRights to store token api access rights
type TokenAccessRights struct {
	APIID       string   `json:"api_id"`
	APIName     string   `json:"api_name"`
	Versions    []string `json:"versions"`
	AllowedURLS []string `json:"allowed_urls"`
	Limit       *string  `json:"limit"`
}

type GolangManifest struct {
	Checksum         string           `json:"checksum"`
	Signature        string           `json:"signature"`
	CustomMiddleware CustomMiddleware `json:"custom_middleware"`
}

type Post struct {
	Name           string `json:"name"`
	Path           string `json:"path"`
	RequireSession bool   `json:"require_session"`
}

type CustomMiddleware struct {
	Post   []Post `json:"post"`
	Driver string `json:"driver"`
}

func apiLoader(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]

	var obj interface{}
	var code int

	switch r.Method {
	// GET remains same - Read apis from memory
	case "GET":
		if apiID != "" {
			log.Debug("Requesting API definition for", apiID)
			obj, code = handleGetAPI(apiID)
		} else {
			log.Debug("Requesting API list")
			obj, code = handleGetAPIList()
		}
	case "POST":
		log.Debug("Creating new definition")
		obj, code = addOrUpdateApi(apiID, r)

	case "DELETE":
		if apiID != "" {
			log.Debug("Deleting API definition for: ", apiID)
			obj, code = deleteAPI(apiID)
		} else {
			obj, code = apiError("Must specify an apiID to delete"), http.StatusBadRequest
		}
	}

	doJSONWrite(w, code, obj)
}

func addOrUpdateApi(apiID string, r *http.Request) (interface{}, int) {
	//var rdb *redis.Client
	var JWTAPIMap = make(map[string]string)
	log.Info("Updating/Adding API to redis")
	c := RedisPool.Get()
	defer c.Close()

	if config.Global().UseDBAppConfigs {
		log.Error("Rejected new API Definition due to UseDBAppConfigs = true")
		return apiError("Due to enabled use_db_app_configs, please use the Dashboard API"), http.StatusInternalServerError
	}

	api := &APIDefinition{}

	if err := json.NewDecoder(r.Body).Decode(api); err != nil {
		log.Error("Couldn't decode new API Definition object: ", err)
		return apiError("Request malformed"), http.StatusBadRequest
	}

	if apiID != "" && api.APIID != apiID {
		log.Error("PUT operation on different APIIDs")
		return apiError("Request APIID does not match that in Definition! For Updtae operations these must match."), http.StatusBadRequest
	}

	//Check if mtls files are present
	_, err := os.Stat(TykServerCrt)
	if os.IsNotExist(err) {
		return apiError("apigw server cert not found. Try after some time"), http.StatusInternalServerError
	}

	_, err = os.Stat(TykServerKey)
	if os.IsNotExist(err) {
		return apiError("apigw server key not found. Try after some time"), http.StatusInternalServerError
	}

	_, err = os.Stat(TykUpstreamPem)
	if os.IsNotExist(err) {
		return apiError("mtls upstream pem not found. Try after some time"), http.StatusInternalServerError
	}

	//Read open and jwt api boilerplate template
	var apiTemplateOpen, apiTemplateJWT, temp map[string]interface{}

	OpenAPI, err := ioutil.ReadFile(APITemplateOpenSpec)
	if err != nil {
		return apiError("Internal Error. Try after some time"), http.StatusInternalServerError
	}

	err = json.Unmarshal(OpenAPI, &apiTemplateOpen)
	if err != nil {
		return apiError("Internal Error. Try after some time"), http.StatusInternalServerError
	}

	JWTAPI, err := ioutil.ReadFile(APITemplateJWTSpec)
	if err != nil {
		return apiError("Internal Error. Try after some time"), http.StatusInternalServerError
	}
	err = json.Unmarshal(JWTAPI, &apiTemplateJWT)
	if err != nil {
		return apiError("Internal Error. Try after some time"), http.StatusInternalServerError
	}

	platform, err := getPlatform(SystemConfigFilePath)
	if err != nil {
		return apiError("Could not get platform type"), http.StatusInternalServerError
	}

	host, err := getInbandIP(SystemConfigFilePath)
	if err != nil {
		return apiError("Could not get inband IP"), http.StatusInternalServerError
	}

	if Contains(api.Platforms, platform) {
		switch api.AuthType {
		case "open":
			temp = apiTemplateOpen
		case "jwt":
			temp = apiTemplateJWT
		default:
			return apiError("Unsupported auth type. It should be either open or jwt"), http.StatusBadRequest
		}

		temp["name"] = api.Name
		temp["api_id"] = api.APIID
		temp["slug"] = api.Slug

		//update target host
		if api.UpdateTargetHost {
			api.TargetURL = strings.Replace(api.TargetURL, "localhost", host, 1)
		}
		temp["proxy"].(map[string]interface{})["target_url"] = api.TargetURL

		temp["proxy"].(map[string]interface{})["listen_path"] = api.ListenPath
		if len(api.URLRewrites) > 0 {
			temp["version_data"].(map[string]interface {
			})["versions"].(map[string]interface {
			})["Default"].(map[string]interface {
			})["extended_paths"].(map[string]interface {
			})["url_rewrites"] = api.URLRewrites
		}

		// Inject middleware
		if api.EnablePythonMiddleware {
			log.Info("Adding custom middleware folder for python", api.Name)
			temp["custom_middleware_bundle"] = TykMiddlewareBundleName
			temp["config_data"] = api.PythonMiddlewareConfigData

			// Create api_hash folder under middleware
			middlewareBundlePath := strings.Join([]string{
				TykMiddlewareRoot, "/", TykBundles, "/", api.APIID, "_", TykMiddlewareBundleNameHash}, "")

			if _, err := os.Stat(middlewareBundlePath); os.IsNotExist(err) {
				// make folder and copy manifest and middleware.py to it
				err := os.MkdirAll(middlewareBundlePath, os.ModePerm)
				if err != nil {
					return apiError("Middleware Error"), http.StatusInternalServerError
				}

				middlewareDestination := strings.Join([]string{middlewareBundlePath, "/", TykMiddlewareFile}, "")
				middlewareSource := strings.Join([]string{TykMiddlewareSrcFile}, "")
				_, mErr := copyFile(middlewareSource, middlewareDestination)
				if mErr != nil {
					return apiError("Middleware Error"), http.StatusInternalServerError
				}

				manifestDestination := strings.Join([]string{middlewareBundlePath, "/", TykManifest}, "")
				manifestSource := strings.Join([]string{TykMiddlewareManifestSrcFile}, "")
				_, maErr := copyFile(manifestSource, manifestDestination)
				if maErr != nil {
					return apiError("Middleware Error"), http.StatusInternalServerError
				}

				log.Info("Added custom middleware folder for %s", api.Name)
			}
		}

		if api.EnableGolangMiddleware {
			log.Info("Adding custom middleware folder for golang %s", api.Name)
			temp["custom_middleware_bundle"] = TykMiddlewareBundleName
			//golang plugin does not have support for config_data

			// Create api_hash folder under middleware
			middlewareBundlePath := strings.Join([]string{
				TykMiddlewareRoot, "/", TykBundles, "/", api.APIID, "_", TykMiddlewareBundleNameHash}, "")

			middlewareBundlePathInK8S := strings.Join([]string{
				TykMiddlewareRoot, "/", TykBundles, "/", api.APIID, "_", TykMiddlewareBundleNameHash}, "")

			if _, err := os.Stat(middlewareBundlePath); os.IsNotExist(err) {
				// make folder and copy manifest and middleware.py to it
				err := os.MkdirAll(middlewareBundlePath, os.ModePerm)
				if err != nil {
					return apiError("Middleware Error"), http.StatusInternalServerError
				}

				//Copy shared object ".so" pointed by path to respective bundle folder
				middlewareDestination := strings.Join([]string{middlewareBundlePath, "/", api.GolangMiddlewareConfigData.Path}, "")
				middlewareSource := strings.Join([]string{TykRoot, "/", api.GolangMiddlewareConfigData.Path}, "")
				_, mErr := copyFile(middlewareSource, middlewareDestination)
				if mErr != nil {
					return apiError("Middleware Error"), http.StatusInternalServerError
				}

				//Read sample manifest file and marshel through the structure
				sharedObjectAbsPathInK8S := strings.Join(
					[]string{middlewareBundlePathInK8S, "/", api.GolangMiddlewareConfigData.Path}, "")

				gm := GolangManifest{Checksum: "", Signature: ""}
				post := Post{Name: api.GolangMiddlewareConfigData.Name, Path: sharedObjectAbsPathInK8S, RequireSession: false}
				gm.CustomMiddleware.Post = append(gm.CustomMiddleware.Post, post)
				gm.CustomMiddleware.Driver = "goplugin"

				data, gErr := json.MarshalIndent(gm, "", "  ")
				if gErr != nil {
					return apiError("Middleware Error"), http.StatusInternalServerError
				}

				manifestDestination := strings.Join([]string{middlewareBundlePath, "/", TykManifest}, "")

				err = ioutil.WriteFile(manifestDestination, data, 0644)
				if err != nil {
					return apiError("Middleware Error"), http.StatusInternalServerError
				}

				log.Info("Added golang middleware folder for %s", api.Name)
			}
		}

		if api.EnableMTLS {
			var certs = map[string]string{}

			certs["*"] = TykUpstreamPem
			temp["upstream_certificates"] = certs
		}

		//temp has the definition - add it to Redis
		apiJSON, _ := json.Marshal(temp)
		_, err = c.Do("SET", api.APIID, apiJSON)
		if err != nil {
			return apiError("Could not add api to redis store"), http.StatusInternalServerError
		}

	} else {
		log.Warn("Platform Missmatch .. skip adding: %s ", api.Name)
	}

	//TODO
	//If JWT API - read all existing JWT enabled apis, add new api_id and update the JWT token
	apis, err := redis.Strings(c.Do("KEYS", "*"))
	if err != nil {
		return apiError("Could not get jwt enabled APIs"), http.StatusInternalServerError
	}

	for _, api := range apis {
		data, err := redis.String(c.Do("GET", api))
		if err != nil {
			return apiError("Error reading API from Redis"), http.StatusInternalServerError
		}

		var jsonApi map[string]interface{}
		err = json.Unmarshal([]byte(data), &jsonApi)

		if jsonApi["enable_jwt"] == true {
			apiID := jsonApi["api_id"].(string)
			name := jsonApi["name"].(string)
			JWTAPIMap[apiID] = name
		}
		log.Info(JWTAPIMap)
	}

	if len(JWTAPIMap) > 0 {
		//Add JWT KEY - go over JWT Definition, add and update all Keys
		var jwtDefinitions JWTDefinitions
		var tykConf map[string]interface{}

		data, err := ioutil.ReadFile(JWTDefinitionsSpec)
		if err != nil {
			return apiError("Error reading JWT Spec"), http.StatusInternalServerError
		}

		err = json.Unmarshal(data, &jwtDefinitions)
		if err != nil {
			return apiError("Error decoding JWT Spec"), http.StatusInternalServerError
		}

		tykConfData, err := ioutil.ReadFile(TykConfFilePath)
		if err != nil {
			return apiError("Error reading TyK conf"), http.StatusInternalServerError
		}

		err = json.Unmarshal(tykConfData, &tykConf)
		if err != nil {
			return apiError("Error decoding TyK conf"), http.StatusInternalServerError
		}

		for _, jwtMeta := range jwtDefinitions.JWTDefinitions {
			count := 0
			for {
				time.Sleep(1 * time.Second)
				ret := createJWTApiKey(tykConf, JWTAPIMap, jwtMeta.JWTPublicKeyPath, jwtMeta.JWTAPIKeyPath, "localhost")
				count++
				if ret == true {
					break
				} else if count < 5 {
					log.Warn("Could not verify JWT API Token.. retry")
				} else {
					log.Error("Could not add JWT token")
					return apiError("Error creating JWT key"), http.StatusInternalServerError
				}
			}
		}
	}

	action := "modified"
	if r.Method == "POST" {
		action = "added"
	}

	response := apiModifyKeySuccess{
		Key:    api.APIID,
		Status: "ok",
		Action: action,
	}

	reloadURLStructure(nil)

	return response, http.StatusOK
}

func createJWTApiKey(tykConf map[string]interface{},
	jwtAPIMap map[string]string, jwtPublicKeyPath string, jwtAPIKeyPath string,
	host string) bool {

	var APIList = make(map[string]TokenAccessRights)
	var template map[string]interface{}

	//Read JWT Public key
	JWTPublicKey, err := ioutil.ReadFile(jwtPublicKeyPath)
	if err != nil {
		log.Error("Error Reading jwt public key")
		return false
	}

	//Read JWT API Key
	//TODO - Add retry flow if key is missing
	JWTApiKey, err := ioutil.ReadFile(jwtAPIKeyPath)
	if err != nil {
		log.Error("Error Reading jwt private key")
		return false
	}

	for key, value := range jwtAPIMap {
		c := TokenAccessRights{APIID: key, APIName: value, Versions: []string{"Default"}, AllowedURLS: []string{}, Limit: nil}
		APIList[key] = c
	}

	//Read token_jwt.json template
	JWTTokenTemplate, err := ioutil.ReadFile(JWTApiKeySpec)
	if err != nil {
		log.Error("Error reading jwt api key template")
		return false
	}
	err = json.Unmarshal(JWTTokenTemplate, &template)
	if err != nil {
		log.Error("Error decoding jwt api key templated")
		return false
	}
	template["access_rights"] = APIList
	template["jwt_data"].(map[string]interface{})["secret"] = string(JWTPublicKey)
	outputJSON, _ := json.Marshal(template)

	//Create Token
	client, ret := GetHTTPClient()
	if ret == false {
		return ret
	}

	JWTKey := strings.TrimSuffix(string(JWTApiKey), "\n")

	var endPoint = getTykEndpoint(host, TykJWTAPIKeyEndpoint) + JWTKey

	req, err := retryablehttp.NewRequest("POST", endPoint, bytes.NewReader(outputJSON))
	if err != nil {
		log.Error("Error creating jwt api key POST request", err)
		return false
	}

	req.Header.Add("x-tyk-authorization", tykConf["secret"].(string))
	log.Info("Creating JWT Token: %s", string(JWTApiKey))
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Error in jwt api key POST", err)
		return false
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Error reading response body", err)
		return false
	}

	if resp.StatusCode == 200 {
		log.Info("Created JWT API Token")
		//Check if the key was really created
		ret := checkIfJwtKeyCreated(tykConf, JWTKey, host)
		if !ret {
			return ret
		}
	} else {
		log.Error("Error Creating JWT API Token")
		return false
	}

	return true
}

func GetHTTPClient() (*retryablehttp.Client, bool) {
	caCert, err := ioutil.ReadFile(TykCACert)
	if err != nil {
		log.Error("Error reading TykCACert")
		return nil, false
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caCertPool},
	}

	httpClient := &http.Client{Timeout: time.Second * 10, Transport: tr}

	client := retryablehttp.NewClient()
	client.HTTPClient = httpClient
	client.RetryMax = 2
	client.RetryWaitMin = 1 * time.Second
	client.RetryWaitMax = 30 * time.Second
	client.CheckRetry = checkRetry

	return client, true
}

func checkIfJwtKeyCreated(tykConf map[string]interface{}, jwtKey string, host string) bool {
	client, _ := GetHTTPClient()

	var endPoint = getTykEndpoint(host, TykJWTAPIKeyEndpoint) + jwtKey

	req, err := retryablehttp.NewRequest("GET", endPoint, nil)
	if err != nil {
		log.Error("Error creating GET reuest", err)
		return false
	}

	req.Header.Add("x-tyk-authorization", tykConf["secret"].(string))
	log.Info("Checking if JWT Token present: %s", jwtKey)
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Error creating GET reuest", err)
		return false
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Error creating GET reuest", err)
		return false
	}

	if resp.StatusCode == 200 {
		log.Info("JWT Token found!")
	} else {
		log.Error("Could not find JWT Token")
		return false
	}

	return true
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// do not retry on context.Canceled or context.DeadlineExceeded
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		return true, err
	}
	if resp.StatusCode != 200 {
		return true, nil
	}

	return false, nil
}

func deleteAPI(apiID string) (interface{}, int) {
	c := RedisPool.Get()
	log.Info("Deleting API from redis")

	defer c.Close()

	// Load API Definition from Redis DB
	_, err := redis.String(c.Do("GET", apiID))
	if err != nil {
		log.Warning("API does not exists ", err)
		return apiError("Api does not exists"), http.StatusInternalServerError
	}

	// Load API Definition from Redis DB
	_, err = c.Do("DEL", apiID)
	if err != nil {
		log.Warning("Error deleting API ", err)
		return apiError("Delete failed"), http.StatusInternalServerError
	}

	response := apiModifyKeySuccess{
		Key:    apiID,
		Status: "ok",
		Action: "deleted",
	}

	//Also delete the middleware folder if it was created
	mwFolder := TykBundlesFolder + "/" + apiID + "_" + TykMiddlewareBundleNameHash
	err = RemoveDirContents(mwFolder)
	if err != nil {
		log.Error("Error deleting bundle folder", err)
	}

	reloadURLStructure(nil)

	return response, http.StatusOK
}

func getPlatform(SysConfPath string) (string, error) {
	var ret = "aci"
	data := make(map[interface{}]interface{})
	SysConfData, err := ioutil.ReadFile(SysConfPath)

	err = yaml.Unmarshal(SysConfData, &data)
	if err != nil {
		return "", err
	}

	if val, found := data["mode"]; found {
		if val == "standalone" {
			ret = "mso"
		}
	}

	return ret, nil
}

func getInbandIP(SysConfPath string) (string, error) {

	type InBandNet struct {
		Subnet    string `yaml:"subnet"`
		Iface     string `yaml:"iface"`
		GatewayIP string `yaml:"gatewayIP"`
		IfaceIP   string `yaml:"ifaceIP"`
	}

	type Inband struct {
		InBandNetwork InBandNet `yaml:"inbandNetwork"`
	}

	var data Inband

	SysConfData, err := ioutil.ReadFile(SysConfPath)

	err = yaml.Unmarshal(SysConfData, &data)
	if err != nil {
		return "", err
	}

	return data.InBandNetwork.IfaceIP, nil
}

func RemoveDirContents(dir string) error {
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		names, err := d.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, name := range names {
			err = os.RemoveAll(filepath.Join(dir, name))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func getTykEndpoint(host string, path string) string {
	url := url.URL{
		Scheme: "https",
		Host:   host + ":" + TykHTTPPort,
		Path:   path,
	}
	return url.String()
}
