package main

import (
	"io"
	"net/http"
)

// proxyToLogServer forwards an approval API request to the log server admin
// endpoint. It:
//   - Strips any X-Sudo-Logger-Decided-By header from the incoming browser
//     request to prevent identity spoofing.
//   - Sets X-Sudo-Logger-Decided-By from decidedBy, which must be derived
//     from the authenticated replay-server session (not from request headers).
//   - Adds the shared bearer token so the log server can authenticate the call.
func proxyToLogServer(w http.ResponseWriter, r *http.Request, targetURL, token, decidedBy string) {
	if q := r.URL.RawQuery; q != "" {
		targetURL += "?" + q
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "approval proxy: build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))

	// Identity comes from the authenticated session, never from the browser.
	if decidedBy != "" && decidedBy != "-" {
		req.Header.Set("X-Sudo-Logger-Decided-By", decidedBy)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
