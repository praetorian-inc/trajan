//go:build ignore

// Local static server for the Trajan browser UI.
//
// Serves browser/ on :8080. Optionally proxies Azure DevOps and self-hosted
// GitLab when CORS blocks direct fetch — enable with TRAJAN_WASM_PROXY=1.
//
//	go run server.go
package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/azdo-proxy/", handleADOProxy)
	mux.HandleFunc("/cors-proxy/", handleCORSProxy)

	fs := http.FileServer(http.Dir("."))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".wasm") {
			w.Header().Set("Content-Type", "application/wasm")
		}
		fs.ServeHTTP(w, r)
	}))

	addr := ":8080"
	log.Printf("Trajan browser UI at http://localhost%s", addr)
	if os.Getenv("TRAJAN_WASM_PROXY") == "1" {
		log.Printf("CORS proxy enabled: /azdo-proxy/ and /cors-proxy/")
	} else {
		log.Printf("CORS proxy disabled (cloud GitHub/GitLab/ADO usually work direct). Set TRAJAN_WASM_PROXY=1 if needed.")
	}
	log.Fatal(http.ListenAndServe(addr, mux))
}

func proxyEnabled(w http.ResponseWriter) bool {
	if os.Getenv("TRAJAN_WASM_PROXY") == "1" {
		return true
	}
	http.Error(w, "proxy disabled; set TRAJAN_WASM_PROXY=1", http.StatusServiceUnavailable)
	return false
}

func isAllowedADOHost(host string) bool {
	if host == "dev.azure.com" || strings.HasSuffix(host, ".dev.azure.com") {
		return true
	}
	parts := strings.Split(host, ".")
	return len(parts) >= 3 && parts[len(parts)-2] == "visualstudio" && parts[len(parts)-1] == "com"
}

func handleADOProxy(w http.ResponseWriter, r *http.Request) {
	if !proxyEnabled(w) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/azdo-proxy/")
	idx := strings.Index(trimmed, "/")
	var host, restPath string
	if idx == -1 {
		host, restPath = trimmed, "/"
	} else {
		host, restPath = trimmed[:idx], trimmed[idx:]
	}
	if host == "" || !isAllowedADOHost(host) {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	forward(w, r, "https", host, restPath)
}

// /cors-proxy/{host}/{path} — allowlisted self-hosted GitLab fallback.
func handleCORSProxy(w http.ResponseWriter, r *http.Request) {
	if !proxyEnabled(w) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, PRIVATE-TOKEN")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/cors-proxy/")
	idx := strings.Index(trimmed, "/")
	var host, restPath string
	if idx == -1 {
		host, restPath = trimmed, "/"
	} else {
		host, restPath = trimmed[:idx], trimmed[idx:]
	}
	if host == "" || host == "169.254.169.254" || strings.HasPrefix(host, "metadata.") {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	scheme := "https"
	if r.URL.Query().Get("scheme") == "http" {
		scheme = "http"
	}
	forward(w, r, scheme, host, restPath)
}

func forward(w http.ResponseWriter, r *http.Request, scheme, host, restPath string) {
	target := &url.URL{Scheme: scheme, Host: host, Path: restPath, RawQuery: r.URL.RawQuery}
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hop := map[string]bool{
		"Connection": true, "Keep-Alive": true, "Proxy-Connection": true,
		"Transfer-Encoding": true, "Upgrade": true,
	}
	for k, vs := range r.Header {
		if hop[k] {
			continue
		}
		for _, v := range vs {
			proxyReq.Header.Add(k, v)
		}
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(proxyReq)
	if err != nil {
		http.Error(w, "proxy failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if hop[k] || k == "Www-Authenticate" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
