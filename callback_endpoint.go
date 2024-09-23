package oidc

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"
)

type callbackEndpoint struct {
	server           *http.Server
	code             string
	errorMsg         string
	errorDescription string
	shutdownSignal   chan string
}

func (h *callbackEndpoint) start() {
	h.shutdownSignal = make(chan string)

	server := &http.Server{
		Addr:           "localhost:9555",
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	h.server = server
	http.Handle("/callback", h)

	go func() {
		server.ListenAndServe()
	}()
}

func (h *callbackEndpoint) stop() {
	h.server.Shutdown(context.Background())
}

func (h *callbackEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintf(os.Stderr, "receiving callback: %s\n", r.URL.String())

	h.code = r.URL.Query().Get("code")
	h.errorDescription = r.URL.Query().Get("error_description")
	h.errorMsg = r.URL.Query().Get("error")

	if h.code != "" {
		tmpl, _ := template.ParseFiles("html/callback-success.html")
		tmpl.Execute(w, nil)
	} else {
		tmpl, _ := template.ParseFiles("html/callback-failure.html")
		tmpl.Execute(w, map[string]string{"errorMsg": h.errorMsg, "errorDescription": h.errorDescription})
	}
	h.shutdownSignal <- "shutdown"
}
