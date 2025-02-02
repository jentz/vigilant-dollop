package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"

	oidc "github.com/jentz/vigilant-dollop"
)

type CommandRunner interface {
	Run() error
}

type Command struct {
	Name      string
	Help      string
	Configure func(name string, args []string, cfg *oidc.Config) (config CommandRunner, output string, err error)
}

var commands = []Command{
	{Name: "authorization_code", Help: "Uses the authorization code flow to get a token response", Configure: parseAuthorizationCodeFlags},
	{Name: "client_credentials", Help: "Uses the client credentials flow to get a token response", Configure: parseClientCredentialsFlags},
	{Name: "introspect", Help: "Uses the introspection flow to validate a token and fetch the associated claims", Configure: parseIntrospectFlags},
	{Name: "token_refresh", Help: "Uses the token refresh flow to exchange a refresh token and obtain new tokens", Configure: parseTokenRefreshFlags},
	{Name: "help", Help: "Prints help"},
}

func usage() {
	intro := `oidc-cli is a command-line OIDC client, get a token without all the fuss

Usage:
  oidc-cli [flags] <command> [command-flags]`

	fmt.Fprintln(os.Stderr, intro)
	fmt.Fprintln(os.Stderr, "\nCommands:")
	for _, cmd := range commands {
		fmt.Fprintf(os.Stderr, "  %-18s: %s\n", cmd.Name, cmd.Help)
	}

	fmt.Fprintln(os.Stderr, "\nFlags:")
	// Prints a help string for each flag we defined earlier using
	// flag.BoolVar (and related functions)
	flag.PrintDefaults()

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Run `oidc-cli <command> -h` to get help for a specific command\n\n")
}

func runCommand(name string, args []string, globalConf *oidc.Config) {

	cmdIdx := slices.IndexFunc(commands, func(cmd Command) bool {
		return cmd.Name == name
	})

	if cmdIdx < 0 {
		fmt.Fprintf(os.Stderr, "command \"%s\" not found\n\n", name)
		flag.Usage()
		os.Exit(1)
	}

	cmd := commands[cmdIdx]
	if cmd.Name == "help" {
		flag.Usage()
		os.Exit(0)
	}

	command, output, err := cmd.Configure(name, args, globalConf)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprintf(os.Stderr, "error: %v\n", output)
		os.Exit(2)
	} else if err != nil {
		fmt.Println("got error:", err)
		fmt.Println("output:\n", output)
		os.Exit(1)
	}

	if err := command.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err.Error())
		os.Exit(1)
	}
}

func main() {
	flag.Usage = usage

	globalConf, args, output, err := parseGlobalFlags("global flags", os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		fmt.Println(output)
		os.Exit(2)
	} else if err != nil {
		fmt.Println("got error:", err)
		fmt.Println("output:\n", output)
		os.Exit(1)
	}

	// If no command is specified, print usage and exit
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}

	subCmd := args[0]
	subCmdArgs := args[1:]
	runCommand(subCmd, subCmdArgs, globalConf)
}
