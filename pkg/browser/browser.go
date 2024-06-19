package browser

import "os/exec"

func OpenURL(url string) error {
	return openBrowser(url)
}

func runCmd(prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	return cmd.Run()
}
