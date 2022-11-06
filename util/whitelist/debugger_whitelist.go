package whitelist

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

var (
	whiteListURL   string
	whiteListCache = cache.New(5*time.Minute, 5*time.Minute)
)

func init() {
	whiteListURL = os.Getenv("WHITELIST_BACKEND_URL")
	logrus.Info("whiteListURL: ", whiteListURL)
}

// IsIPValid checks if the debugger IP is in the whitelist through the whitelist backend
func IsIPValid(ip string) (bool, error) {
	// in dev environment
	if whiteListURL == "" {
		return true, nil
	}
	if ip == "unknown_ip" {
		return false, nil
	}

	cacheKey := "whitelist-ip-" + ip
	cacheValue, found := whiteListCache.Get(cacheKey)
	logrus.Debug("whitelist IP cache Get ip: ", ip, ", found: ", found, ", valid: ", valid)
	if found {
		return cacheValue.(bool), nil
	}

	params := url.Values{}
	Url, err := url.Parse(whiteListURL + "api/get_debugger")
	if err != nil {
		return false, err
	}
	params.Set("accept", "application/json")
	params.Set("ip", ip)
	Url.RawQuery = params.Encode()
	urlPath := Url.String()
	resp, err := http.Get(urlPath)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return false, err
	}

	debuggerList, ok := data["debugger"]
	isValid := (ok == true) && (debuggerList != nil)
	whiteListCache.Set(cacheKey, isValid, cache.DefaultExpiration)
	return isValid, nil
}

func GetIPFromRequestEnv(req *http.Request) string {
	fwdAddress := req.Header.Get("X-Forwarded-For")
	if fwdAddress != "" {
		return strings.ToLower(strings.Split(fwdAddress, ", ")[0])
	}
	ip := req.Header.Get("X-Real-IP")
	if ip != "" {
		return strings.ToLower(ip)
	}
	ip = strings.Split(req.RemoteAddr, ":")[0]
	if ip != "" {
		return strings.ToLower(ip)
	}
	return "unknown_ip"
}
