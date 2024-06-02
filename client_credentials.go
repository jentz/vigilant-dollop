package oidc

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type ClientCredentialsFlow struct {
	ServerConfig *ServerConfig
	ClientConfig *ClientConfig
}

func NewClientCredentialsFlow(serverConf *ServerConfig, clientConf *ClientConfig) *ClientCredentialsFlow {
	return &ClientCredentialsFlow {
		ServerConfig: serverConf,
		ClientConfig: clientConf,
	}
}

func (c *ClientCredentialsFlow) Run() error {
	vals := url.Values{}
	vals.Set("grant_type", "client_credentials")
	vals.Set("client_id", c.ClientConfig.ClientID)
	vals.Set("client_secret", c.ClientConfig.ClientSecret)

	req, err := http.NewRequest("POST", c.ServerConfig.TokenEndpoint, strings.NewReader(vals.Encode()))
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
