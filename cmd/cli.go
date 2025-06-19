package cmd

import (
	"errors"
	"flag"

	"github.com/jentz/oidc-cli/log"
)

const (
	ExitOK = iota
	ExitError
	ExitHelp
)

// CLI runs the main CLI logic and returns an exit code.
// Optionally accepts a logger to allow test output capture.
func CLI(args []string, logOptions ...log.Option) int {
	logger := log.New(logOptions...)
	flag.Usage = func() {
		usage(logger)
	}

	globalConf, args, output, err := ParseGlobalFlags("global flags", args)
	if errors.Is(err, flag.ErrHelp) {
		logger.Errorln(output)
		return ExitHelp
	} else if err != nil {
		logger.Errorln("got error:", err)
		logger.Errorln("output:\n", output)
		return ExitError
	}

	// If no command is specified, print usage and exit
	if len(args) < 1 {
		usage(logger)
		return ExitError
	}

	subCmd := args[0]
	subCmdArgs := args[1:]
	return RunCommand(subCmd, subCmdArgs, globalConf, logger)
}

func usage(logger *log.Logger) {
	intro := `oidc-cli is a command-line OIDC client, get a token without all the fuss

Usage:
  oidc-cli [flags] <command> [command-flags]`

	logger.Outputln(intro)
	logger.Outputln("\nCommands:")
	for _, command := range commands {
		logger.Outputf("  %-18s: %s\n", command.Name, command.Help)
	}

	logger.Outputln("\nFlags:")
	// Prints a help string for each flag we defined earlier using
	// flag.BoolVar (and related functions)
	flag.PrintDefaults()

	logger.Outputln()
	logger.Outputf("Run `oidc-cli <command> -h` to get help for a specific command\n\n")
}
