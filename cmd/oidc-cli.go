package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
)

type Command struct {
	Name  string
	Help  string
	Parse func(name string, args []string) (config interface{}, output string, err error)
	Run   func(config interface{}) error
}

var commands = []Command{
	{Name: "authorization_code", Help: "Uses the authorization code flow to get a token response", Parse: parseAuthorizationCodeFlags, Run: authorizationCodeCmd},
	{Name: "client_credentials", Help: "Uses the client credentials flow to get a token response", Run: clientCredentialsCmd},
	{Name: "help", Help: "Prints help", Run: helpCmd},
}

func helpCmd(_ interface{}) error {
	flag.Usage()
	return nil
}

func clientCredentialsCmd(config interface{}) error {
	return nil
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

func runCommand(name string, args []string) {

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
		cmd.Run(nil)
		return
	}

	config, output, err := cmd.Parse(name, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Println(output)
		os.Exit(2)
	} else if err != nil {
		fmt.Println("got error:", err)
		fmt.Println("output:\n", output)
		os.Exit(1)
	}

	if err := cmd.Run(config); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err.Error())
		os.Exit(1)
	}
}

func main() {
	flag.Usage = usage
	flag.Parse()

	// If no command is specified, print usage and exit
	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	subCmd := flag.Arg(0)
	subCmdArgs := flag.Args()[1:]
	runCommand(subCmd, subCmdArgs)
}
