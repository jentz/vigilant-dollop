package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"slices"
	"syscall"

	oidc "github.com/jentz/vigilant-dollop"
	"github.com/jentz/vigilant-dollop/pkg/log"
)

type CommandRunner interface {
	Run(ctx context.Context) error
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
	{Name: "version", Help: "Prints the version of oidc-cli"},
	{Name: "help", Help: "Prints help"},
}

func usage() {
	intro := `oidc-cli is a command-line OIDC client, get a token without all the fuss

Usage:
  oidc-cli [flags] <command> [command-flags]`

	log.Outputln(intro)
	log.Outputln("\nCommands:")
	for _, cmd := range commands {
		log.Outputf("  %-18s: %s\n", cmd.Name, cmd.Help)
	}

	log.Outputln("\nFlags:")
	// Prints a help string for each flag we defined earlier using
	// flag.BoolVar (and related functions)
	flag.PrintDefaults()

	log.Outputln()
	log.Outputf("Run `oidc-cli <command> -h` to get help for a specific command\n\n")
}

func runCommand(name string, args []string, globalConf *oidc.Config) {
	cmdIdx := slices.IndexFunc(commands, func(cmd Command) bool {
		return cmd.Name == name
	})

	if cmdIdx < 0 {
		log.Errorf("command \"%s\" not found\n\n", name)
		flag.Usage()
		os.Exit(1)
	}

	cmd := commands[cmdIdx]
	if cmd.Name == "help" {
		flag.Usage()
		os.Exit(0)
	}

	if cmd.Name == "version" {
		log.Outputln("oidc-cli version:", oidc.Version)
		os.Exit(0)
	}

	command, output, err := cmd.Configure(name, args, globalConf)
	if errors.Is(err, flag.ErrHelp) {
		log.Errorf("error: %v\n", output)
		os.Exit(2)
	} else if err != nil {
		log.Errorln("got error:", err)
		log.Errorln("output:\n", output)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-signalChan
		log.Errorf("\nreceived signal: %s, cancelling...\n", sig)
		cancel()
	}()

	defer func() {
		cancel()
		signal.Stop(signalChan)
		close(signalChan)
	}()

	if err := command.Run(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			log.Errorln("operation cancelled")
			os.Exit(0)
		} else if errors.Is(err, context.DeadlineExceeded) {
			log.Errorln("operation timed out")
			os.Exit(1)
		}
		log.Errorf("error: %v\n", err.Error())
		os.Exit(1)
	}
}

func main() {
	flag.Usage = usage

	globalConf, args, output, err := parseGlobalFlags("global flags", os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		log.Errorln(output)
		os.Exit(2)
	} else if err != nil {
		log.Errorln("got error:", err)
		log.Errorln("output:\n", output)
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
