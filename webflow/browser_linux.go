package webflow

func openBrowser(url string, runCmd func(string, ...string) error) error {
	return runCmd("xdg-open", url)
}
