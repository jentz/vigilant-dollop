package main

import (
	"flag"
	"fmt"
	oidc "github.com/jentz/vigilant-dollop"
	"log"
)

func main() {

	const callbackURL = "http://localhost:9555/callback"
	flag.Usage = func() {
		fmt.Println("Usage: oidc-cli\n" +
			"       setup an openid client with the callback url : " + callbackURL + " and set below flags to get a token response\n" +
			"Flags:\n" +
			"      --authorization-url	authorization URL. Default value is https://localhost:9443/oauth2/authorize.\n" +
			"      --token-url        	token URL. Default value is https://localhost:9443/oauth2/token\n" +
			"      --client-id       	client ID.\n" +
			"      --client-secret    	client secret.")
	}

	var authorizationEndpoint = flag.String("authorization-url", "https://localhost:9443/oauth2/authorize", "OAuth2 authorization URL")
	var tokenEndpoint = flag.String("token-url", "https://localhost:9443/oauth2/token", "OAuth2 token URL")
	var clientID = flag.String("client-id", "client", "OAuth2 client ID")
	var clientSecret = flag.String("client-secret", "clientSecret", "OAuth2 client secret")

	flag.Parse()
	if *clientID == "" {
		log.Fatal("clientID is required to run this command")
	} else if *clientSecret == "" {
		log.Fatal("clientID is required to run this command")
	}
	oidc.HandleOpenIDFlow(*clientID, *clientSecret, callbackURL, *authorizationEndpoint, *tokenEndpoint)
}
