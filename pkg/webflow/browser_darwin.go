package webflow

func openBrowser(url string) error {
	return runCmd("open", url)
}
