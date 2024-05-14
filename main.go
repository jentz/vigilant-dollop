package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {

	const callbackURL = "http://localhost:9555/callback"
	flag.Usage = func() {
		fmt.Println("Usage: openid-client \n" +
			"       setup an openid client with the callback url : " + callbackURL + " and set below flags to get a token response\n" +
			"Flags:\n" +
			"      --authorizationURL	authorization URL. Default value is https://localhost:9443/oauth2/authorize.\n" +
			"      --tokenURL        	token URL. Default value is https://localhost:9443/oauth2/token\n" +
			"      --clientID        	client ID.\n" +
			"      --clientSecret    	client secret.")
	}

	var authorizationEndpoint = flag.String("authorizationURL", "https://localhost:9443/oauth2/authorize", "OAuth2 authorization URL")
	var tokenEndpoint = flag.String("tokenURL", "https://localhost:9443/oauth2/token", "OAuth2 token URL")
	var clientID = flag.String("clientID", "client", "OAuth2 client ID")
	var clientSecret = flag.String("clientSecret", "clientSecret", "OAuth2 client secret")

	flag.Parse()
	if *clientID == "" {
		log.Fatal("clientID is required to run this command")
	} else if *clientSecret == "" {
		log.Fatal("clientID is required to run this command")
	}
	HandleOpenIDFlow(*clientID, *clientSecret, callbackURL, *authorizationEndpoint, *tokenEndpoint)
}
