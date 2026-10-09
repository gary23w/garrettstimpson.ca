package server

import "net/http"

func (s *Server) webuiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "The front end is not embedded into this binary (next dev for development; build with -tags embedui for release)", http.StatusNotFound)
	})
}
