package webflow

func openBrowser(url string) error {
	return runCmd("rundll32", "url.dll,FileProtocolHandler", url)
}
