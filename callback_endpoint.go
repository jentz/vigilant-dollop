package oidc

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"time"
)

//go:embed html/*
var content embed.FS

type callbackEndpoint struct {
	server           *http.Server
	code             string
	errorMsg         string
	errorDescription string
	shutdownSignal   chan string
}

func (h *callbackEndpoint) start(addr, path string, verbose bool) {
	h.shutdownSignal = make(chan string)

	server := &http.Server{
		Addr:           addr,
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	h.server = server
	http.Handle(path, h)

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot listen on callback endpoint, port not available %s\n", server.Addr)
		os.Exit(1)
	}
	ln.Close()

	go func() {
		server.ListenAndServe()
	}()

	if verbose {
		fmt.Fprintf(os.Stderr, "started http server for callback endpoint %s%s\n", server.Addr, path)
	}
}

func (h *callbackEndpoint) stop() {
	h.server.Shutdown(context.Background())
}

func (h *callbackEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	h.code = r.URL.Query().Get("code")
	h.errorDescription = r.URL.Query().Get("error_description")
	h.errorMsg = r.URL.Query().Get("error")

	if h.code != "" {
		h.renderSuccess(w)
	} else {
		h.renderError(w)
	}
	h.shutdownSignal <- "shutdown"
}

func (h *callbackEndpoint) renderError(w http.ResponseWriter) {
	tmpl, err := template.ParseFS(content, "html/callback-error.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "error parsing error template: %v\n", err)
		return
	}
	if err := tmpl.Execute(w, map[string]string{"errorMsg": h.errorMsg, "errorDescription": h.errorDescription}); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "error executing error template: %v\n", err)
		return
	}
}

func (h *callbackEndpoint) renderSuccess(w http.ResponseWriter) {
	tmpl, err := template.ParseFS(content, "html/callback-success.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "error parsing success template: %v\n", err)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "error executing success template: %v\n", err)
		return
	}
}
