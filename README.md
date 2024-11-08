# vigilant-dollop
Command-line OIDC client, get a token without all the fuss

## Usage

```bash
oidc-cli is a command-line OIDC client, get a token without all the fuss

Usage:
  oidc-cli [flags] <command> [command-flags]

Commands:
  authorization_code: Uses the authorization code flow to get a token response
  client_credentials: Uses the client credentials flow to get a token response
  introspect        : Uses the introspection flow to validate a token and fetch the associated claims
  token_refresh     : Uses the token refresh flow to exchange a refresh token and obtain new tokens
  help              : Prints help

Flags:

Run `oidc-cli <command> -h` to get help for a specific command
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
go run ./cmd authorization_code --authorization-url <authorization-url> --token-url <token-url> --client-id <client-id> --client-secret <client-secret> --scopes "openid profile"
```

## Test

```bash
go test -v ./...
```
    
## Build

```bash
 go build -v -o oidc-cli ./cmd
```

