package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

type callbackEndpoint struct {
	server         *http.Server
	code           string
	shutdownSignal chan string
}

func (h *callbackEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintf(os.Stderr, "callback URL %s\n", r.URL.String())

	code := r.URL.Query().Get("code")
	if code != "" {
		h.code = code
		fmt.Fprintln(w, "Login is successful, You may close the browser and return to the commandline")
	} else {
		fmt.Fprintln(w, "Login is not successful, You may close the browser and try again")
	}
	h.shutdownSignal <- "shutdown"
}

func randomString(n int) string {
    b := make([]byte, n)
    _, err := rand.Read(b)
    if err != nil {
        log.Fatal(err)
    }
    return base64.URLEncoding.EncodeToString(b)[0:n-1]
}

func randomInt(min, max int) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
    if err != nil {
        log.Fatal(err)
    }
    return int(nBig.Int64()) + min
}


func HandleOpenIDFlow(clientID, clientSecret, scopes, callbackURL, discoveryEndpoint, authorizationEndpoint, tokenEndpoint string, pkce bool) {

	callbackEndpoint := &callbackEndpoint{}
	callbackEndpoint.shutdownSignal = make(chan string)
	server := &http.Server{
		Addr:           "localhost:9555",
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	callbackEndpoint.server = server
	http.Handle("/callback", callbackEndpoint)

	if discoveryEndpoint != "" {
		resp, err := http.Get(discoveryEndpoint)
		if err != nil {
			log.Fatal(err)
		}
		var discoveryJson map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&discoveryJson)
		authorizationEndpoint = discoveryJson["authorization_endpoint"].(string)
		tokenEndpoint = discoveryJson["token_endpoint"].(string)
	}

	authURL, authURLParseError := url.Parse(authorizationEndpoint)
	if authURLParseError != nil {
		log.Fatal(authURLParseError)
	}
	query := authURL.Query()
	query.Set("client_id", clientID)
	query.Set("response_type", "code")
	query.Set("scope", scopes)
	query.Set("redirect_uri", callbackURL)

	var codeVerifier string
	if pkce {
		codeVerifier = randomString(randomInt(43, 128))
		sha256Sum := sha256.Sum256([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(sha256Sum[:])
		query.Set("code_challenge_method", "S256")
		query.Set("code_challenge", codeChallenge)
	}
	authURL.RawQuery = query.Encode()

	fmt.Fprintf(os.Stderr, "authURL is %s\n", authURL.String())
	cmd := exec.Command("open", authURL.String())
	err := cmd.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to open browser, visit %s to continue\n", authURL.String())
	}

	go func() {
		server.ListenAndServe()
	}()

	<-callbackEndpoint.shutdownSignal
	callbackEndpoint.server.Shutdown(context.Background())
	fmt.Fprintf(os.Stderr, "authorization code is %s\n", callbackEndpoint.code)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	vals := url.Values{}
	vals.Set("grant_type", "authorization_code")
	vals.Set("code", callbackEndpoint.code)
	vals.Set("redirect_uri", callbackURL)
	if pkce {
		vals.Set("code_verifier", codeVerifier)
	}
	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(vals.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result != nil {
		jsonStr, marshalError := json.Marshal(result)
		if marshalError != nil {
			log.Fatal(marshalError)
		}
		fmt.Println(string(jsonStr))
	} else {
		log.Fatalln("Error while getting ID token")
	}
}
