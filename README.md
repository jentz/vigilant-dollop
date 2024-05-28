# vigilant-dollop
Command-line OIDC client, get a token without all the fuss

## Usage

```bash
Usage: oidc-cli [flags]
       setup an openid client with the callback url : http://localhost:9555/callback and set below flags to get a token response
Flags:
        --discovery-url         OpenID discovery endpoint. If provided, authorization-url and token-url will be ignored.
        --authorization-url     authorization URL. Default value is https://localhost:9443/oauth2/authorize.
        --token-url             token URL. Default value is https://localhost:9443/oauth2/token
        --client-id             client ID.
        --client-secret         client secret.
        --scopes                scopes.
```
## Installing

Installing with homebrew
```bash
 brew tap jentz/vigilant-dollop
 brew install oidc-cli
 ```

You can also download a suitable release for your platform from the [releases page](https://github.com/jentz/vigilant-dollop/releases).

## Run

```bash
go run cmd/oidc-cli.go --authorization-url <authorization-url> --token-url <token-url> --client-id <client-id> --client-secret <client-secret>
```


## Build

```bash
go build  cmd/oidc-cli.go
```

