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
	"strings"

	"cspm-dashboard/backend/models"
)

// attackPathsRequest is the body accepted by POST /api/attack-paths.
type attackPathsRequest struct {
	Findings []models.Finding `json:"findings"`
}

// handleAttackPaths accepts a findings array, forwards a compact representation
// to the Claude API, and returns the structured attack paths JSON directly.
func (s *Server) handleAttackPaths(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req attackPathsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Findings) == 0 {
		writeError(w, http.StatusBadRequest, "findings array is empty")
		return
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		writeError(w, http.StatusInternalServerError, "ANTHROPIC_API_KEY is not configured on the server")
		return
	}

	result, err := callClaudeAttackPaths(r.Context(), apiKey, req.Findings)
	if err != nil {
		log.Printf("[attack-paths] Claude error: %v", err)
		writeError(w, http.StatusBadGateway, "AI service error: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}

const attackPathSystemPrompt = `You are a cloud security expert that analyzes AWS security findings and identifies realistic attack paths — chains of misconfigurations an attacker could exploit in sequence to achieve a goal like data exfiltration, privilege escalation, or full account takeover.

Given a list of security findings (each with an "id" field), identify 1-3 realistic attack paths as a directed graph where steps can branch.

Rules:
1. Every step's "finding_id" MUST exactly match one of the "id" values in the provided findings list. Do not invent or guess finding IDs — copy them verbatim.
2. Every step within a single path must have a unique "action" label — never repeat the same action string twice in the same path's steps array.
3. At least one path must contain a node with two or more entries in "next_steps" (a branching node) to show how an attacker pivots in multiple directions after gaining access.
4. Use "next_steps": [] for terminal (leaf) nodes with no further steps.
5. All step IDs must be unique strings within the path, e.g. "s1", "s2", "s3". The first step in the array is the entry point (root).
6. Assign overall path severity: Critical, High, or Medium.
7. Include 2-5 relevant MITRE ATT&CK tactic names in "mitre_tactics". Each tactic name must be unique within the list.

Return ONLY valid JSON with no markdown, no backticks, no explanation outside the JSON object. Use this exact structure:
{"attack_paths": [{"id": "path-1", "goal": "Full Account Takeover", "severity": "Critical", "narrative": "An attacker exploits open SSH access to gain a foothold, then branches: escalating IAM privileges for persistent access while simultaneously exfiltrating S3 data.", "steps": [{"id": "s1", "finding_id": "<exact_id_from_input>", "action": "Initial Access", "detail": "Exploit unrestricted SSH access on port 22", "next_steps": ["s2", "s3"]}, {"id": "s2", "finding_id": "<exact_id_from_input>", "action": "Privilege Escalation", "detail": "No MFA allows credential stuffing on IAM console", "next_steps": []}, {"id": "s3", "finding_id": "<exact_id_from_input>", "action": "Exfiltration", "detail": "Public S3 bucket exposes customer data directly", "next_steps": []}], "mitre_tactics": ["Initial Access", "Privilege Escalation", "Exfiltration"]}]}`

// attackStep is a single node in the attack graph.
type attackStep struct {
	ID        string   `json:"id"`
	FindingID string   `json:"finding_id"`
	Action    string   `json:"action"`
	Detail    string   `json:"detail"`
	NextSteps []string `json:"next_steps"`
}

// attackPath is one complete attack scenario with a directed graph of steps.
type attackPath struct {
	ID           string       `json:"id"`
	Goal         string       `json:"goal"`
	Severity     string       `json:"severity"`
	Narrative    string       `json:"narrative"`
	Steps        []attackStep `json:"steps"`
	MitreTactics []string     `json:"mitre_tactics"`
}

// attackPathsResponse is the top-level JSON shape returned by Claude and the API.
type attackPathsResponse struct {
	AttackPaths []attackPath `json:"attack_paths"`
}

// slimFinding is the compact representation sent to Claude to keep the prompt short.
type slimFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Service     string `json:"service"`
	Severity    string `json:"severity"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
	CISControl  string `json:"cis_control,omitempty"`
}

// validateAndClean removes steps whose finding_id is not in the input findings,
// prunes next_steps references to dropped nodes, drops paths with fewer than 2
// valid steps, and deduplicates action labels within each path.
func validateAndClean(response *attackPathsResponse, findings []models.Finding) {
	validIDs := make(map[string]bool, len(findings))
	for _, f := range findings {
		validIDs[f.ID] = true
	}

	kept := response.AttackPaths[:0]
	for pi := range response.AttackPaths {
		path := &response.AttackPaths[pi]

		// Filter steps whose finding_id does not match any real finding.
		validStepIDs := map[string]bool{}
		filtered := []attackStep{}
		for _, s := range path.Steps {
			if validIDs[s.FindingID] {
				filtered = append(filtered, s)
				validStepIDs[s.ID] = true
			} else {
				log.Printf("[attack-paths] dropping step %s: finding_id %q not in input", s.ID, s.FindingID)
			}
		}

		// Prune next_steps references that point to dropped nodes.
		for i := range filtered {
			keptNext := []string{}
			for _, nid := range filtered[i].NextSteps {
				if validStepIDs[nid] {
					keptNext = append(keptNext, nid)
				}
			}
			filtered[i].NextSteps = keptNext
		}
		path.Steps = filtered

		if len(path.Steps) < 2 {
			log.Printf("[attack-paths] dropping path %s: only %d valid steps", path.ID, len(path.Steps))
			continue
		}

		// Deduplicate action labels within this path. If two steps share an
		// action name, disambiguate the second with the first words of its detail.
		seen := map[string]bool{}
		for i := range path.Steps {
			action := path.Steps[i].Action
			if seen[action] {
				words := strings.Fields(path.Steps[i].Detail)
				if len(words) > 3 {
					words = words[:3]
				}
				path.Steps[i].Action = action + " — " + strings.Join(words, " ")
			}
			seen[path.Steps[i].Action] = true
		}

		kept = append(kept, *path)
	}
	response.AttackPaths = kept
}

func callClaudeAttackPaths(ctx context.Context, apiKey string, findings []models.Finding) (json.RawMessage, error) {
	slim := make([]slimFinding, 0, len(findings))
	for _, f := range findings {
		slim = append(slim, slimFinding{
			ID:          f.ID,
			Title:       f.Title,
			Service:     f.Service,
			Severity:    string(f.Severity),
			Resource:    f.ResourceName,
			Description: f.Description,
			CISControl:  f.CISControl,
		})
	}

	findingsJSON, err := json.Marshal(slim)
	if err != nil {
		return nil, fmt.Errorf("marshalling findings: %w", err)
	}

	reqBody := map[string]any{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 2048,
		"system":     attackPathSystemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": string(findingsJSON)},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshalling Claude request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling Claude API: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Claude API returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var claudeResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBytes, &claudeResp); err != nil {
		return nil, fmt.Errorf("parsing Claude envelope: %w", err)
	}

	for _, block := range claudeResp.Content {
		if block.Type != "text" {
			continue
		}

		var response attackPathsResponse
		if err := json.Unmarshal([]byte(block.Text), &response); err != nil {
			return nil, fmt.Errorf("Claude returned invalid JSON: %w", err)
		}

		validateAndClean(&response, findings)

		result, err := json.Marshal(response)
		if err != nil {
			return nil, fmt.Errorf("re-marshalling validated response: %w", err)
		}
		return result, nil
	}
	return nil, fmt.Errorf("no text block in Claude response")
}
