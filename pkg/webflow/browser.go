package webflow

import "os/exec"

type Browser interface {
	Open(url string) error
}

type SystemBrowser struct{}

func NewSystemBrowser() *SystemBrowser {
	return &SystemBrowser{}
}

func (s *SystemBrowser) Open(url string) error {
	return openBrowser(url)
}

func runCmd(prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	return cmd.Run()
}
