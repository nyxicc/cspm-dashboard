// Package api implements the HTTP server, route registration, and middleware
// for the CSPM dashboard backend.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"cspm-dashboard/backend/models"
	"cspm-dashboard/backend/scanners"
	"cspm-dashboard/backend/scanners/azure"
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
	mux.HandleFunc("/api/explain", s.handleExplain)
	mux.HandleFunc("/api/attack-paths", s.handleAttackPaths)

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
//
// Set provider to "aws" (or omit it) for AWS scanning, or "azure" for Azure.
// Only the fields relevant to the chosen provider need to be supplied.
type ScanRequest struct {
	// Provider selects the cloud platform to scan. "aws" (default) or "azure".
	Provider string `json:"provider"`

	// AWS credentials — required when provider is "aws" (or omitted).
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"` // optional — for temporary/STS creds
	Region          string `json:"region"`

	// Azure Service Principal credentials — required when provider is "azure".
	SubscriptionID string `json:"subscription_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	TenantID       string `json:"tenant_id"`
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
	if err := validateScanRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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

// handleSummary accepts cloud credentials, runs a full scan, and returns
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
	if err := validateScanRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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

// handleExplain accepts a single Finding in the POST body, calls the Claude
// API to generate a plain-English risk explanation, and returns it as JSON.
// The Anthropic API key is read from the ANTHROPIC_API_KEY environment variable
// and is never forwarded to or exposed by the frontend.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var finding models.Finding
	if err := json.NewDecoder(r.Body).Decode(&finding); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		writeError(w, http.StatusInternalServerError, "ANTHROPIC_API_KEY is not configured on the server")
		return
	}

	explanation, err := callClaude(r.Context(), apiKey, &finding)
	if err != nil {
		log.Printf("[explain] Claude API error: %v", err)
		writeError(w, http.StatusBadGateway, "AI service error: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"explanation": explanation})
}

// claudeSystemPrompt is the persona and instruction set sent to Claude for
// every explain request.
const claudeSystemPrompt = `You are a cloud security expert explaining AWS misconfigurations to a security team. Always respond using exactly these four labeled sections and no other text:

**What it is:** [One sentence explaining the specific misconfiguration on this resource]
**Why it's dangerous:** [One sentence on the concrete security risk this creates]
**Attack scenario:** [One to two sentences describing exactly what an attacker would do with this exposure, using the actual resource name]
**Immediate fix:** [One to two sentences of specific, actionable remediation steps]

Be technical and direct. Use the actual resource names and service names from the finding.`

// callClaude sends the finding details to the Claude API and returns the
// generated explanation text.
func callClaude(ctx context.Context, apiKey string, f *models.Finding) (string, error) {
	userMsg := fmt.Sprintf(
		"Title: %s\nService: %s\nSeverity: %s\nAffected Resource: %s (%s)\nRegion: %s\nCIS Control: %s\nDescription: %s\nRecommendation: %s",
		f.Title, f.Service, f.Severity,
		f.ResourceName, f.ResourceType,
		f.Region, f.CISControl,
		f.Description, f.Recommendation,
	)

	reqBody := map[string]any{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 1024,
		"system":     claudeSystemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": userMsg},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling Claude API: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Claude API returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return "", fmt.Errorf("parsing Claude response: %w", err)
	}
	for _, block := range result.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("no text block in Claude response")
}

// =============================================================================
// Scanner factory
// =============================================================================

// validateScanRequest checks that the required credential fields are present
// for the chosen provider.
func validateScanRequest(req ScanRequest) error {
	switch req.Provider {
	case "", "aws":
		if req.AccessKeyID == "" || req.SecretAccessKey == "" || req.Region == "" {
			return fmt.Errorf("access_key_id, secret_access_key, and region are required for AWS")
		}
	case "azure":
		if req.SubscriptionID == "" || req.ClientID == "" ||
			req.ClientSecret == "" || req.TenantID == "" {
			return fmt.Errorf("subscription_id, client_id, client_secret, and tenant_id are required for Azure")
		}
	default:
		return fmt.Errorf("provider must be \"aws\" or \"azure\"")
	}
	return nil
}

// buildScanners dispatches to the correct provider's scanner factory based on
// the provider field in the request.
func buildScanners(ctx context.Context, req ScanRequest) ([]scanners.Scanner, error) {
	switch req.Provider {
	case "", "aws":
		return buildAWSScanners(ctx, req)
	case "azure":
		return buildAzureScanners(ctx, req)
	default:
		return nil, fmt.Errorf("unknown provider: %s", req.Provider)
	}
}

// buildAWSScanners creates an AWS config from the provided static credentials,
// validates them via STS GetCallerIdentity, and returns a ready-to-use
// scanner slice.
//
// sts:GetCallerIdentity requires no IAM permissions — any valid identity can
// call it — so a failure here reliably means the credentials are wrong or
// expired.
func buildAWSScanners(ctx context.Context, req ScanRequest) ([]scanners.Scanner, error) {
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
		scanners.NewRDSScanner(cfg, accountID),
		scanners.NewGuardDutyScanner(cfg, accountID),
		scanners.NewConfigScanner(cfg, accountID),
		scanners.NewSecurityHubScanner(cfg, accountID),
		scanners.NewLambdaScanner(cfg, accountID),
		scanners.NewKMSScanner(cfg, accountID),
		scanners.NewEFSScanner(cfg, accountID),
		scanners.NewAccessAnalyzerScanner(cfg, accountID),
	}, nil
}

// buildAzureScanners validates the Azure Service Principal credentials and
// returns the full set of Azure scanners.
func buildAzureScanners(ctx context.Context, req ScanRequest) ([]scanners.Scanner, error) {
	return azure.BuildScanners(ctx, azure.Credentials{
		SubscriptionID: req.SubscriptionID,
		ClientID:       req.ClientID,
		ClientSecret:   req.ClientSecret,
		TenantID:       req.TenantID,
	})
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
