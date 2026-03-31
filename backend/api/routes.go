// Package api implements the HTTP server, route registration, and middleware
// for the CSPM dashboard backend.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"cspm-dashboard/backend/models"
	"cspm-dashboard/backend/scanners"
)

// scanTimeout is the maximum time a full scan may run before it is cancelled.
const scanTimeout = 5 * time.Minute

// Server holds shared HTTP server state. Scanners are created per-request
// from credentials supplied in the POST body, so nothing credential-related
// lives here.
type Server struct{}

// NewServer creates a Server ready to serve HTTP requests.
func NewServer() *Server {
	return &Server{}
}

// Handler returns the fully configured HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/findings/summary", s.handleSummary)

	var h http.Handler = mux
	h = corsMiddleware(h)
	h = loggingMiddleware(h)
	return h
}

// =============================================================================
// Request / Response types
// =============================================================================

// ScanRequest is the JSON body accepted by POST /api/scan and
// POST /api/findings/summary. Credentials are used for that request only —
// they are never stored.
type ScanRequest struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`  // optional — for temporary/STS creds
	Region          string `json:"region"`
}

// scanError records a scanner failure without aborting the overall response.
type scanError struct {
	Service string `json:"service"`
	Message string `json:"message"`
}

// ScanResponse is returned by POST /api/scan.
type ScanResponse struct {
	ScannedAt  time.Time        `json:"scanned_at"`
	DurationMs int64            `json:"duration_ms"`
	TotalCount int              `json:"total_count"`
	Findings   []models.Finding `json:"findings"`
	Errors     []scanError      `json:"errors,omitempty"`
}

// SummaryResponse is returned by POST /api/findings/summary.
type SummaryResponse struct {
	ScannedAt     time.Time      `json:"scanned_at"`
	DurationMs    int64          `json:"duration_ms"`
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByService     map[string]int `json:"by_service"`
	Errors        []scanError    `json:"errors,omitempty"`
}

// =============================================================================
// Handlers
// =============================================================================

// handleHealth is a lightweight liveness check. It never triggers a scan.
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

// handleScan accepts AWS credentials in the POST body, builds scanners from
// them, runs a full concurrent scan, and returns all findings as JSON.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.AccessKeyID == "" || req.SecretAccessKey == "" || req.Region == "" {
		writeError(w, http.StatusBadRequest, "access_key_id, secret_access_key, and region are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
	defer cancel()

	sc, err := buildScanners(ctx, req)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	start := time.Now()
	findings, errs := runScan(ctx, sc)
	elapsed := time.Since(start)

	writeJSON(w, http.StatusOK, ScanResponse{
		ScannedAt:  start.UTC(),
		DurationMs: elapsed.Milliseconds(),
		TotalCount: len(findings),
		Findings:   findings,
		Errors:     errs,
	})
}

// handleSummary accepts AWS credentials, runs a full scan, and returns
// finding counts grouped by severity and service.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.AccessKeyID == "" || req.SecretAccessKey == "" || req.Region == "" {
		writeError(w, http.StatusBadRequest, "access_key_id, secret_access_key, and region are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
	defer cancel()

	sc, err := buildScanners(ctx, req)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	start := time.Now()
	findings, errs := runScan(ctx, sc)
	elapsed := time.Since(start)

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
// Scanner factory
// =============================================================================

// buildScanners creates an AWS config from the provided static credentials,
// validates them via STS GetCallerIdentity, and returns a ready-to-use
// scanner slice.
//
// sts:GetCallerIdentity requires no IAM permissions — any valid identity can
// call it — so a failure here reliably means the credentials are wrong or
// expired.
func buildScanners(ctx context.Context, req ScanRequest) ([]scanners.Scanner, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(req.Region),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				req.AccessKeyID,
				req.SecretAccessKey,
				req.SessionToken,
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	accountID := aws.ToString(identity.Account)
	log.Printf("[scan] account: %s | region: %s", accountID, req.Region)

	return []scanners.Scanner{
		scanners.NewS3Scanner(cfg, accountID),
		scanners.NewIAMScanner(cfg, accountID),
		scanners.NewEC2Scanner(cfg, accountID),
		scanners.NewCloudTrailScanner(cfg, accountID),
	}, nil
}

// =============================================================================
// Scan orchestration
// =============================================================================

// runScan runs every scanner concurrently and collects all findings.
func runScan(ctx context.Context, sc []scanners.Scanner) ([]models.Finding, []scanError) {
	resultCh := make(chan scanners.ScanResult, len(sc))

	for _, scanner := range sc {
		scanner := scanner
		go func() {
			findings, err := scanner.Scan(ctx)
			resultCh <- scanners.ScanResult{
				ServiceName: scanner.ServiceName(),
				Findings:    findings,
				Err:         err,
			}
		}()
	}

	var allFindings []models.Finding
	var errs []scanError

	for range sc {
		result := <-resultCh
		if result.Err != nil {
			log.Printf("[scan] %s scanner error: %v", result.ServiceName, result.Err)
			errs = append(errs, scanError{
				Service: result.ServiceName,
				Message: result.Err.Error(),
			})
		}
		allFindings = append(allFindings, result.Findings...)
	}

	return allFindings, errs
}

// =============================================================================
// Middleware
// =============================================================================

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &recordingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("[http] %s %s → %d (%s)",
			r.Method, r.URL.Path, rw.statusCode, time.Since(start))
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

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

type recordingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *recordingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[api] json encode error: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
