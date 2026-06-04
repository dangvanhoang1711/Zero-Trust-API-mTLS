package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
)

type echoResponse struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := echoResponse{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: cloneHeaders(r.Header),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("encode response failed: %v", err)
		}
	})

	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	if tlsCertFile == "" {
		tlsCertFile = "/etc/internal-tls/tls.crt"
	}
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	if tlsKeyFile == "" {
		tlsKeyFile = "/etc/internal-tls/tls.key"
	}

	log.Printf("echo service listening on :%s (TLS)", port)
	if err := http.ListenAndServeTLS(":"+port, tlsCertFile, tlsKeyFile, h); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func cloneHeaders(headers http.Header) map[string][]string {
	out := make(map[string][]string, len(headers))
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		values := headers.Values(key)
		normalized := make([]string, 0, len(values))
		for _, value := range values {
			normalized = append(normalized, strings.TrimSpace(value))
		}
		out[key] = normalized
	}

	return out
}
