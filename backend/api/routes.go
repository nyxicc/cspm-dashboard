// Package api implements the HTTP server, route registration, and middleware
// for the CSPM dashboard backend.
package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"cspm-dashboard/backend/models"
	"cspm-dashboard/backend/scanners"
)

// scanTimeout is the maximum time a full scan may run before it is cancelled.
// AWS API calls are generally fast, but large accounts with many resources can
// take longer. Adjust this if scans time out in your environment.
const scanTimeout = 5 * time.Minute

// Server holds the dependencies shared across all HTTP handlers.
// Keeping them here (rather than as package-level globals) makes the server
// easy to test: construct a Server with mock scanners, call Handler(), done.
type Server struct {
	scanners []scanners.Scanner
}

// NewServer creates a Server wired up with the provided scanners.
func NewServer(sc []scanners.Scanner) *Server {
	return &Server{scanners: sc}
}

// Handler returns the fully configured HTTP handler for the server.
// Routes are registered on an internal mux, then wrapped with middleware.
// Middleware is applied inside-out: loggingMiddleware is outermost (executes
// first on the way in, last on the way out), corsMiddleware is next.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/findings/summary", s.handleSummary)

	// Chain middleware. Each layer wraps the next, so the call order is:
	// request → logging → CORS → mux → handler → CORS → logging → response
	var h http.Handler = mux
	h = corsMiddleware(h)
	h = loggingMiddleware(h)
	return h
}

// =============================================================================
// Response types
// =============================================================================

// scanError records a scanner failure without aborting the overall response.
// Partial results (findings from successful scanners) are still returned even
// when some scanners fail.
type scanError struct {
	Service string `json:"service"`
	Message string `json:"message"`
}

// ScanResponse is returned by GET /api/scan.
type ScanResponse struct {
	ScannedAt  time.Time        `json:"scanned_at"`
	DurationMs int64            `json:"duration_ms"`
	TotalCount int              `json:"total_count"`
	Findings   []models.Finding `json:"findings"`
	// Errors is omitted from JSON when empty so a clean scan has no noise.
	Errors []scanError `json:"errors,omitempty"`
}

// SummaryResponse is returned by GET /api/findings/summary.
type SummaryResponse struct {
	ScannedAt     time.Time      `json:"scanned_at"`
	DurationMs    int64          `json:"duration_ms"`
	TotalFindings int            `json:"total_findings"`
	// BySeverity always includes all four severity levels, even if their count
	// is zero. This lets the frontend render the full breakdown without having
	// to handle missing keys.
	BySeverity map[string]int `json:"by_severity"`
	// ByService only includes services for which at least one finding exists.
	ByService map[string]int `json:"by_service"`
	Errors    []scanError    `json:"errors,omitempty"`
}

// =============================================================================
// Handlers
// =============================================================================

// handleHealth is a lightweight liveness check for load balancers and
// monitoring systems. It never triggers a scan — it only confirms the
// process is running and can serve HTTP.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleScan triggers a full concurrent scan across all configured services
// and returns the complete list of findings as JSON.
//
// Because scans hit live AWS APIs, response times depend on the number of
// resources in the account. The scan runs with a 5-minute context timeout;
// if the client disconnects before that, the underlying AWS calls are
// cancelled via context propagation.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Wrap the request context with a timeout so a hung AWS API call cannot
	// block the server indefinitely.
	ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
	defer cancel()

	start := time.Now()
	findings, errs := s.runScan(ctx)
	elapsed := time.Since(start)

	writeJSON(w, http.StatusOK, ScanResponse{
		ScannedAt:  start.UTC(),
		DurationMs: elapsed.Milliseconds(),
		TotalCount: len(findings),
		Findings:   findings,
		Errors:     errs,
	})
}

// handleSummary triggers a full scan and returns finding counts grouped by
// severity and by service, without the full finding payloads. Useful for
// dashboard overview widgets that only need aggregate numbers.
//
// In a production system with high-volume accounts, this endpoint would read
// from a cached/stored scan result rather than triggering a live scan on every
// request. For this initial implementation, every call runs a fresh scan.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
	defer cancel()

	start := time.Now()
	findings, errs := s.runScan(ctx)
	elapsed := time.Since(start)

	// Pre-populate all four severity levels at zero so the frontend always
	// receives a complete map regardless of what the scan found.
	bySeverity := map[string]int{
		string(models.SeverityCritical): 0,
		string(models.SeverityHigh):     0,
		string(models.SeverityMedium):   0,
		string(models.SeverityLow):      0,
	}
	byService := make(map[string]int)

	for _, f := range findings {
		bySeverity[string(f.Severity)]++
		byService[f.Service]++
	}

	writeJSON(w, http.StatusOK, SummaryResponse{
		ScannedAt:     start.UTC(),
		DurationMs:    elapsed.Milliseconds(),
		TotalFindings: len(findings),
		BySeverity:    bySeverity,
		ByService:     byService,
		Errors:        errs,
	})
}

// =============================================================================
// Scan orchestration
// =============================================================================

// runScan runs every scanner concurrently and collects all findings.
//
// Each scanner runs in its own goroutine and sends its result on a buffered
// channel. The buffer is sized to len(s.scanners) so no goroutine ever blocks
// on a send — the main goroutine drains the channel afterwards at its own pace.
// This is the standard Go fan-out/fan-in pattern.
//
// If a scanner returns an error, its findings (which may be partial) are still
// included and the error is surfaced in the response separately. This "best
// effort" approach means one misconfigured scanner cannot hide findings from
// the others.
func (s *Server) runScan(ctx context.Context) ([]models.Finding, []scanError) {
	// Buffered so goroutines never block waiting for the receiver.
	resultCh := make(chan scanners.ScanResult, len(s.scanners))

	for _, sc := range s.scanners {
		sc := sc // capture loop variable — each goroutine needs its own copy
		go func() {
			findings, err := sc.Scan(ctx)
			resultCh <- scanners.ScanResult{
				ServiceName: sc.ServiceName(),
				Findings:    findings,
				Err:         err,
			}
		}()
	}

	// Collect exactly len(s.scanners) results. Because the channel is buffered
	// to that size and every goroutine always sends exactly one result (even on
	// error), this loop always terminates without a deadlock.
	var allFindings []models.Finding
	var errs []scanError

	for range s.scanners {
		result := <-resultCh
		if result.Err != nil {
			log.Printf("[scan] %s scanner error: %v", result.ServiceName, result.Err)
			errs = append(errs, scanError{
				Service: result.ServiceName,
				Message: result.Err.Error(),
			})
		}
		// Append findings even when Err is non-nil — scanners may return
		// partial results alongside an error (e.g., succeeded on 9 of 10 pages).
		allFindings = append(allFindings, result.Findings...)
	}

	return allFindings, errs
}

// =============================================================================
// Middleware
// =============================================================================

// loggingMiddleware logs every incoming request with its method, path, status
// code, and how long the handler took to respond. It wraps the ResponseWriter
// in a thin recorder so the status code written by the handler is visible after
// the fact.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &recordingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("[http] %s %s → %d (%s)",
			r.Method, r.URL.Path, rw.statusCode, time.Since(start))
	})
}

// corsMiddleware adds the HTTP headers required for browsers to make
// cross-origin requests from the React frontend (typically localhost:5173
// with Vite or localhost:3000 with Create React App).
//
// In production, replace the wildcard Access-Control-Allow-Origin with the
// specific domain(s) that are permitted to call this API. A wildcard is
// acceptable here because this server is not expected to be publicly exposed
// — it should sit behind an auth layer or be reachable only from a VPN.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Preflight requests (OPTIONS) are sent automatically by browsers before
		// cross-origin requests. Respond with 204 No Content and stop — the
		// actual request will follow immediately after.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// =============================================================================
// Helpers
// =============================================================================

// recordingResponseWriter wraps http.ResponseWriter to capture the status code
// written by the handler. The standard ResponseWriter does not expose the code
// after WriteHeader is called, so logging middleware cannot read it without
// this wrapper.
type recordingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader intercepts the status code before forwarding to the real writer.
func (rw *recordingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// writeJSON serialises v to JSON and writes it to w with the given status code.
// The Content-Type header is set before WriteHeader so it appears in the
// response even on error status codes.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Encoding errors at this point are unrecoverable — the response has
		// already started. Log and move on.
		log.Printf("[api] json encode error: %v", err)
	}
}

// writeError writes a JSON error response with a single "error" key.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
