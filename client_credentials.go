package oidc

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type ClientCredentialsConfig struct {
	DiscoveryEndpoint     string
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	ClientSecret          string
	Scopes			      string
}

func (c *ClientCredentialsConfig) DiscoverEndpoints() {
	if c.DiscoveryEndpoint != "" {
		resp, err := http.Get(c.DiscoveryEndpoint)
		if err != nil {
			log.Fatal(err)
		}
		var discoveryJson map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&discoveryJson)
		c.AuthorizationEndpoint = discoveryJson["authorization_endpoint"].(string)
		c.TokenEndpoint = discoveryJson["token_endpoint"].(string)
	}
}

func (c *ClientCredentialsConfig) Run() error {
	vals := url.Values{}
	vals.Set("grant_type", "client_credentials")
	vals.Set("client_id", c.ClientID)
	vals.Set("client_secret", c.ClientSecret)

	req, err := http.NewRequest("POST", c.TokenEndpoint, strings.NewReader(vals.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result != nil {
		jsonStr, marshalError := json.Marshal(result)
		if marshalError != nil {
			log.Fatal(marshalError)
		}
		fmt.Println(string(jsonStr))
	} else {
		log.Fatalln("Error while getting token")
	}
	return nil
}
