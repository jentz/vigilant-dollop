# vigilant-dollop
Command-line OIDC client, get a token without all the fuss

## Usage

```bash
Usage: vigilant-dollop 
       setup an openid client with the callback url : http://localhost:9555/callback and set below flags to get a token response
Flags:
      --authorization-url       authorization URL. Default value is https://localhost:9443/oauth2/authorize.
      --token-url               token URL. Default value is https://localhost:9443/oauth2/token
      --client-id               client ID.
      --client-secret           client secret.
```


## Build

```bash
go build -o vigilant-dollop cmd/main.go
```

