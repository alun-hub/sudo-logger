package main

import (
	"io"
	"net/http"
)

// proxyToLogServer forwards a request to the log server admin API and writes
// the response back to w. It is a simple pass-through: headers, body, and
// status code are relayed unchanged.
func proxyToLogServer(w http.ResponseWriter, r *http.Request, targetURL string) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "approval proxy: build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	if v := r.Header.Get("X-Decided-By"); v != "" {
		req.Header.Set("X-Decided-By", v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "approval proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
