# oidc-cli 🚀
Command-line OIDC client, get a token without all the fuss

## Usage 🛠️

```bash
oidc-cli is a command-line OIDC client, get a token without all the fuss

Usage:
  oidc-cli [flags] <command> [command-flags]

Commands:
  authorization_code: Uses the authorization code flow to get a token response
  client_credentials: Uses the client credentials flow to get a token response
  introspect        : Uses the introspection flow to validate a token and fetch the associated claims
  token_refresh     : Uses the token refresh flow to exchange a refresh token and obtain new tokens
  version           : Prints the version of oidc-cli
  help              : Prints help

Flags:

Run `oidc-cli <command> -h` to get help for a specific command
```

## Installing 💾

* Installing with homebrew 🍺
```bash
 brew tap jentz/oidc-cli
 brew install oidc-cli
 ```
* Installing with scoop 🥄
```powershell
 scoop bucket add oidc-cli https://github.com/jentz/scoop-oidc-cli
 scoop install oidc-cli
```

* Installing with go get
```bash
# NOTE: The dev version will be in effect!
go install github.com/jentz/oidc-cli@latest
```

You can also download a suitable release for your platform from the [releases page](https://github.com/jentz/oidc-cli/releases).

## Run ▶️

```bash
go run ./ authorization_code --authorization-url <authorization-url> --token-url <token-url> --client-id <client-id> --client-secret <client-secret> --scopes "openid profile"
```

## Test

```bash
go test -v ./...
```
    
## Build

```bash
 go build -v -o oidc-cli
```
