//go:build !darwin && !linux && !windows
// +build !darwin,!linux,!windows

package webflow

import (
	"fmt"
	"runtime"
)

func openBrowser(url string) error {
	return fmt.Errorf("openBrowser: unsupported operating system: %v", runtime.GOOS)
}
