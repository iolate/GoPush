package main

import (
	"os"
	"sync"
	"flag"
	"path"
	"log"
	"io"
	"io/ioutil"
	"bytes"
	"errors"
	"strconv"
	"net/http"
	"crypto/tls"
	"encoding/json"
	"golang.org/x/net/http2"
	"github.com/alexjlockwood/gcm"
	"time"
	"crypto/x509"
	"encoding/pem"
	"github.com/dgrijalva/jwt-go"
)

const (
	AppTypeAPNS				= "apns"
	AppTypeSandboxAPNS		= "apns_sandbox"
	AppTypeGCM				= "gcm"
	
	APNSServer					= "https://api.push.apple.com"
	DevelopmentAPNSServer		= "https://api.development.push.apple.com"
)
type AppSettings struct {
	Host		string
	Port		string
	ConfPath	string
	BaseDir		string
	LogFile		string
}
type App struct {
	Id			string
	Type		string	`json:"type"`
	Key			string	`json:"key"`
	BundleId	string	`json:"bundle_id"`		// for APNs
	TeamId		string	`json:"team_id"`		// for APNs
	KeyId		string	`json:"key_id"`			// for APNs
}
type APNSHeaders struct {
	Id			string	`json:"apns-id"`
	Expiration	string	`json:"apns-expiration"`
	Priority	string	`json:"apns-priority"`
	Topic		string	`json:"apns-topic"`
}
type APNSResponse struct {
	Reason		string	`json:"reason"`
	Timestamp	string	`json:"timestamp"`
}
type APNSFeedback struct {
	StatusCode	int		`json:"status_code"`	//410
	ApnsId		string	`json:"apns-id"`
	Token		string	`json:"token"`
	Reason		string	`json:"reason"`
	Timestamp	string	`json:"timestamp"`
}
type GCMFeedback struct {
	Token		string	`json:"token"`
	Canonical	string	`json:"canonical"`
	Reason		string	`json:"reason"`			//NotRegistered
}
var apnsFeedbacks map[string][]APNSFeedback = make(map[string][]APNSFeedback)
var mutexApns sync.Mutex
var gcmFeedbacks map[string][]GCMFeedback = make(map[string][]GCMFeedback)
var mutexGcm sync.Mutex

var pushApps map[string]App
var appSettings AppSettings
func main() {
	log.Println("[Info/main] GoPush Start!!")
	
	flag.StringVar(&appSettings.Host, "host", "127.0.0.1", "Listening IP (default: 127.0.0.1)")
	flag.StringVar(&appSettings.Port, "port", "5481", "Listening Port (default: 5481)")
	flag.StringVar(&appSettings.ConfPath, "conf", "", "Configuration JSON File Path (required)")
	flag.StringVar(&appSettings.LogFile, "logfile", "", "Path to log file (default: stdout)")
	flag.Parse()
	
	if appSettings.LogFile != "" {
		f, err := os.OpenFile(appSettings.LogFile, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
		if err != nil {
			log.Fatal("[Error/main] Cannot open log file - ", err)
		}else {
			defer f.Close()
			log.SetOutput(f)
		}
	}
	
	if appSettings.ConfPath == "" {
		log.Fatal("[Error/main] No Configure File!")
		return
	}
	log.Println("[Info/main] Load config ", appSettings.ConfPath)
	
	file, err := ioutil.ReadFile(appSettings.ConfPath)
	if err != nil {
		log.Fatal("[Error/main] Read file - ", err)
		return
	}
	appSettings.BaseDir = path.Dir(appSettings.ConfPath)
	
	err = json.Unmarshal(file, &pushApps)
	if err != nil {
		log.Fatal("[Error/main] Configure unmarshal - ", err)
		return
	}
	for key, val := range pushApps { val.Id = key}
	
	log.Println("[Info/main] Listening Host: ", appSettings.Host)
	log.Println("[Info/main] Listening Port: ", appSettings.Port)
	
	http.HandleFunc("/send", send)
	http.HandleFunc("/feedback", feedback)
	err = http.ListenAndServe(appSettings.Host+":"+appSettings.Port, nil)
	if err != nil {
		log.Fatal("[Error/main] Listen - ", err)
		return
	}
}

//======================================================================================//
func send(w http.ResponseWriter, r *http.Request) {	
	app := r.FormValue("app")
	
	var output string
	if app, ok := pushApps[app]; ok {
		payload := r.FormValue("payload")
		token := r.FormValue("token")
		
		if payload == "" || token == ""{
			w.WriteHeader(http.StatusBadRequest)
			output = "No payload or token"
		}else{
			w.WriteHeader(http.StatusOK)
			output = "success"
			go func() {
				switch app.Type {
				case AppTypeAPNS: fallthrough
				case AppTypeSandboxAPNS:
					headersStr := r.FormValue("headers")
					var headers *APNSHeaders = nil
					if headersStr != "" {
						headers = new(APNSHeaders)
						err := json.Unmarshal([]byte(headersStr), headers)
						if err != nil {
							log.Fatal("[Error/send] headers: ", err)
							headers = nil
						}
					}
					
					err := SendAPNS(&app, token, payload, headers)
					if err != nil {
						log.Fatal("[Error/send] SendAPNS: ", err)
					}
				case AppTypeGCM:
					err := SendGCM(&app, token, payload)
					if err != nil {
						log.Fatal("[Error/send] SendGCM: ", err)
					}
				}
			}()
		}
	}else{
		w.WriteHeader(http.StatusNotFound)
		output = "Unknown app"
	}
	
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(output)))
	io.WriteString(w, output)
}

func feedback(w http.ResponseWriter, r *http.Request) {	
	app := r.FormValue("app")
	
	var output string
	if app, ok := pushApps[app]; ok {
		w.WriteHeader(http.StatusOK)
		output = "null"
		
		if app.Type == AppTypeGCM {
			mutexGcm.Lock()
			dumps, err := json.Marshal(gcmFeedbacks[app.Id])
			gcmFeedbacks[app.Id] = nil
			mutexGcm.Unlock()
			if err == nil { output = string(dumps) }
		}else{
			mutexApns.Lock()
			dumps, err := json.Marshal(apnsFeedbacks[app.Id])
			apnsFeedbacks[app.Id] = nil
			mutexApns.Unlock()
			if err == nil { output = string(dumps) }
		}
		if output == "null" { output = "[]" }
		
		w.Header().Set("Content-Type", "application/json")
	}else{
		w.WriteHeader(http.StatusNotFound)
		output = "Unknown App"
		w.Header().Set("Content-Type", "text/html")
	}
	
	w.Header().Set("Content-Length", strconv.Itoa(len(output)))
	io.WriteString(w, output)
}

//======================================================================================//
func SendAPNS(app *App, token, payload string, headers *APNSHeaders) error {
	var url string
	if app.Type == AppTypeAPNS { 
		url = APNSServer
	}else{ 
		url = DevelopmentAPNSServer
	}
	url += "/3/device/" + token
	
	if app.Key == "" {
		return errors.New("No Cert/Key File")
	}
	
	var keyPath string
	if app.Key[:1] == "/" {
		keyPath = app.Key
	}else if len(app.Key) > 2 && app.Key[:2] == "./" {
		keyPath = appSettings.BaseDir + app.Key[1:]
	}else {
		keyPath = appSettings.BaseDir + "/" + app.Key
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(payload)))
	if err != nil { return err }
	
	var transport *http2.Transport
	if app.KeyId != "" {
		secret_byte, err := ioutil.ReadFile(keyPath)
		if err != nil { return err }
		block, _ := pem.Decode(secret_byte)
		
		secret, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil { return err }
		
		claims := &jwt.StandardClaims{
			Issuer: app.TeamId,
			IssuedAt: time.Now().Unix(),
		}
		auth := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		auth.Header["alg"] = "ES256"
		auth.Header["kid"] = app.KeyId
		authString, err := auth.SignedString(secret)
		if err != nil { return err }
		
		req.Header.Set("authorization", "bearer " + authString)
		req.Header.Set("apns-topic", app.BundleId)
		
		tlsConfig := &tls.Config{
			//InsecureSkipVerify: true,
		}
		transport = &http2.Transport{TLSClientConfig: tlsConfig}
	}else{
		cert, err := tls.LoadX509KeyPair(keyPath, keyPath)
		if err != nil { return err }
		
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			InsecureSkipVerify: true,
		}
		transport = &http2.Transport{TLSClientConfig: tlsConfig}
	}
	
	if headers != nil {
		if headers.Id != "" { req.Header.Set("apns-id", headers.Id) }
		if headers.Expiration != "" { req.Header.Set("apns-expiration", headers.Expiration) }
		if headers.Priority != "" { req.Header.Set("apns-priority", headers.Priority) }
		if headers.Topic != "" { req.Header.Set("apns-topic", headers.Topic) }
	}
	
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil { return err }
	if resp != nil {
		defer resp.Body.Close()
		
		switch resp.StatusCode {
		case 200:
			return nil
		//case 410: //The device token is no longer active for the topic.
		default:
			var feedback APNSFeedback
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil { return err }
			err = json.Unmarshal([]byte(body), &feedback)
			if err != nil { return err }
			
			feedback.StatusCode = resp.StatusCode
			feedback.ApnsId = resp.Header["Apns-Id"][0]
			feedback.Token = token
			
			mutexApns.Lock()
			apnsFeedbacks[app.Id] = append(apnsFeedbacks[app.Id], feedback)
			mutexApns.Unlock()
		}
		return nil
	}else{
		return errors.New("Response is nil")
	}
}

func SendGCM(app *App, token, payload string) error {
	var payloadMap map[string]interface{}
	err := json.Unmarshal([]byte(payload), &payloadMap)
	if err != nil { return err }
	
	msg := gcm.NewMessage(payloadMap, token)
	sender := &gcm.Sender{ApiKey: app.Key}
	response, err := sender.Send(msg, 2)
	if err != nil {
		return err
	}
	
	if response != nil && len(response.Results) > 0 {
		result := response.Results[0]
		
		if result.Error != "" || result.RegistrationID != "" {
			feedback := GCMFeedback{
				Token: token,
				Canonical: result.RegistrationID,
				Reason: result.Error,
			}
			
			mutexGcm.Lock()
			gcmFeedbacks[app.Id] = append(gcmFeedbacks[app.Id], feedback)
			mutexGcm.Unlock()
		}
	}else {
		return errors.New("Response is nil")
	}
	
	return nil
}
