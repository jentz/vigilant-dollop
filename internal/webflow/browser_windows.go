package webflow

func openBrowser(url string, runCmd func(string, ...string) error) error {
	return runCmd("rundll32", "url.dll,FileProtocolHandler", url)
}
