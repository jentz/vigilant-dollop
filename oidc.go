package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jentz/vigilant-dollop/pkg/browser"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
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

func randomInt(min, max int) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		panic(err)
	}
	return int(nBig.Int64()) + min
}

func generateCodeVerifier(n int) string {
	if n < 32 || n > 96 {
		panic("Code verifier length before base64 encoding must be between 32 and 96 bytes")
	}
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	// NoPadding is used to avoid '=' padding characters which are not accepted by the authorization server in the code_verifier parameter
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func calculateCodeChallenge(codeVerifier string) string {
	sha := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

func HandleOpenIDFlow(clientID, clientSecret, scopes, callbackURL, discoveryEndpoint, authorizationEndpoint, tokenEndpoint string, customArgs CustomArgs, usePKCE bool) {

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

	for _, arg := range customArgs {
		kv := strings.SplitN(arg, "=", 2)
		query.Set(kv[0], kv[1])
	}

	var codeVerifier string
	if usePKCE {
		// Starting with a byte array of 32-96 bytes ensures that the base64 encoded string will be between 43 and 128 characters long as required by RFC7636
		codeVerifier = generateCodeVerifier(randomInt(32, 96))
		codeChallenge := calculateCodeChallenge(codeVerifier)
		query.Set("code_challenge_method", "S256")
		query.Set("code_challenge", codeChallenge)
	}

	authURL.RawQuery = query.Encode()

	fmt.Fprintf(os.Stderr, "authURL is %s\n", authURL.String())
	err := browser.OpenURL(authURL.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to open browser because %v, visit %s to continue\n", err, authURL.String())
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
	if usePKCE {
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
