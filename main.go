package main

import (
	"os"

	"github.com/jentz/oidc-cli/cmd"
)

func main() {
	os.Exit(cmd.CLI(os.Args[1:]))
}
