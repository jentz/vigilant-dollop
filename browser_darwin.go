package oidc

func openBrowser(url string) error {
	return runCmd("open", url)
}
