package oidc

func openBrowser(url string) error {
	return runCmd("xdg-open", url)
}
