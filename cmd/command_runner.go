package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/jentz/oidc-cli/log"
	"github.com/jentz/oidc-cli/oidc"
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

func Usage() {
	intro := `oidc-cli is a command-line OIDC client, get a token without all the fuss

Usage:
  oidc-cli [flags] <command> [command-flags]`

	log.Outputln(intro)
	log.Outputln("\nCommands:")
	for _, command := range commands {
		log.Outputf("  %-18s: %s\n", command.Name, command.Help)
	}

	log.Outputln("\nFlags:")
	// Prints a help string for each flag we defined earlier using
	// flag.BoolVar (and related functions)
	flag.PrintDefaults()

	log.Outputln()
	log.Outputf("Run `oidc-cli <command> -h` to get help for a specific command\n\n")
}

func RunCommand(name string, args []string, globalConf *oidc.Config) {
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

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	defer func() {
		signal.Stop(signalChan)
		close(signalChan)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// handle signals
	go func() {
		sig := <-signalChan
		log.Errorf("\nreceived signal: %s, cancelling...\n", sig)
		cancel()
	}()

	// In main.go or cmd.RunCommand
	if err := prepareOIDCConfig(ctx, globalConf); err != nil {
		log.Errorln("configuration error:", err)
		os.Exit(1)
	}

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

func prepareOIDCConfig(ctx context.Context, conf *oidc.Config) error {
	if err := conf.DiscoverEndpoints(ctx); err != nil {
		return fmt.Errorf("failed to discover endpoints: %w", err)
	}
	if err := conf.ReadKeyFiles(); err != nil {
		return fmt.Errorf("failed to read key files: %w", err)
	}
	return nil
}
