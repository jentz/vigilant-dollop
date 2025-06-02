package main

import (
	"errors"
	"flag"
	"os"

	"github.com/jentz/oidc-cli/cmd"
	"github.com/jentz/oidc-cli/log"
)

func main() {
	flag.Usage = cmd.Usage

	globalConf, args, output, err := cmd.ParseGlobalFlags("global flags", os.Args[1:])
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
		cmd.Usage()
		os.Exit(1)
	}

	subCmd := args[0]
	subCmdArgs := args[1:]
	cmd.RunCommand(subCmd, subCmdArgs, globalConf)
}
