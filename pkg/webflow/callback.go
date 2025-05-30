package webflow

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"github.com/jentz/vigilant-dollop/pkg/log"
	"net/http"
	"net/url"
	"text/template"
	"time"
)

//go:embed html/*
var content embed.FS

type CallbackServer struct {
	host     string
	path     string
	server   *http.Server
	response chan *CallbackResponse
}

type CallbackResponse struct {
	Code             string
	ErrorMsg         string
	ErrorDescription string
}

func NewCallbackServer(callbackURI string) (*CallbackServer, error) {
	u, err := url.Parse(callbackURI)
	if err != nil {
		return nil, fmt.Errorf("invalid callback URI: %w", err)
	}

	return &CallbackServer{
		host:     u.Host,
		path:     u.Path,
		response: make(chan *CallbackResponse, 1),
	}, nil
}

func (s *CallbackServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handleCallback)

	s.server = &http.Server{
		Addr:        s.host,
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
	}

	return s.server.ListenAndServe()
}

func (s *CallbackServer) WaitForCallback(ctx context.Context) (*CallbackResponse, error) {
	select {
	case resp := <-s.response:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Minute):
		return nil, errors.New("timeout waiting for callback")
	}
}

func (s *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	var resp CallbackResponse
	var templatePath string

	resp.Code = r.URL.Query().Get("code")
	resp.ErrorMsg = r.URL.Query().Get("error")
	resp.ErrorDescription = r.URL.Query().Get("error_description")

	if resp.Code == "" {
		templatePath = "html/callback-error.html"
		w.WriteHeader(http.StatusBadRequest)
	} else {
		templatePath = "html/callback-success.html"
		w.WriteHeader(http.StatusOK)
	}

	tmpl, err := template.ParseFS(content, templatePath)
	if err != nil {
		log.Errorf("failed to parse template %s: %v", templatePath, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, resp); err != nil {
		log.Errorf("failed to execute template %s: %v", templatePath, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	select {
	case s.response <- &resp:
		// Successfully sent the response
	default:
		log.Errorf("callback response channel is full, dropping response")
	}
}
