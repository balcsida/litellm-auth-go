package testserver

import (
	"net/http"
	"net/http/httptest"
	"sync"
)

type Request struct {
	Method string
	Path   string
	Query  string
	Header http.Header
}

type Server struct {
	*httptest.Server
	mu       sync.Mutex
	requests []Request
}

func New(handler http.HandlerFunc) *Server {
	s := &Server{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone()})
		s.mu.Unlock()
		handler(w, r)
	}))
	return s
}

func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}
