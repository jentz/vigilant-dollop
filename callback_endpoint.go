package oidc

import (
	"context"
	"embed"
	"errors"
	"github.com/jentz/vigilant-dollop/pkg/log"
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
		log.ErrPrintf("cannot listen on callback endpoint, port not available %s\n", server.Addr)
		os.Exit(1)
	}
	err = ln.Close()
	if err != nil {
		return
	}

	go func() {
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.ErrPrintf("http server error: %v\n", err)
		}
	}()

	if verbose {
		log.ErrPrintf("started http server for callback endpoint %s%s\n", server.Addr, path)
	}
}

func (h *callbackEndpoint) stop() {
	if err := h.server.Shutdown(context.Background()); err != nil {
		log.ErrPrintf("error shutting down server: %v\n", err)
	}
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
	select {
	case h.shutdownSignal <- "shutdown":
		// sent successfully
	default:
		log.ErrPrintf("warning: shutdown signal channel blocked or closed\n")
	}
}

func (h *callbackEndpoint) renderError(w http.ResponseWriter) {
	tmpl, err := template.ParseFS(content, "html/callback-error.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.ErrPrintf("error parsing error template: %v\n", err)
		return
	}
	if err := tmpl.Execute(w, map[string]string{"errorMsg": h.errorMsg, "errorDescription": h.errorDescription}); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.ErrPrintf("error executing error template: %v\n", err)
		return
	}
}

func (h *callbackEndpoint) renderSuccess(w http.ResponseWriter) {
	tmpl, err := template.ParseFS(content, "html/callback-success.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.ErrPrintf("error parsing success template: %v\n", err)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.ErrPrintf("error executing success template: %v\n", err)
		return
	}
}
