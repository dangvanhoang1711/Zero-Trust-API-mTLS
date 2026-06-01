package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

type protectedResponse struct {
	Service    string `json:"service"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	User       string `json:"user"`
	CertSubject string `json:"cert_subject"`
	Timestamp  string `json:"timestamp"`
	Message    string `json:"message"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("x-auth-user")
		certSubject := r.Header.Get("x-auth-cert-subject")
		if user == "" {
			http.Error(w, "missing x-auth-user identity", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		response := protectedResponse{
			Service:     "protected-api",
			Method:      r.Method,
			Path:        r.URL.Path,
			User:        user,
			CertSubject: certSubject,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Message:     "Access granted with validated PoP context",
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("encode response failed: %v", err)
		}
	})

	log.Printf("protected API service listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

