// ABOUTME: HTTP handlers for AI-powered NL search and CVE summarization.
// ABOUTME: Handles quota enforcement, caching, DSL compilation, and request logging.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/ai"
	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/metrics"
	"github.com/scarson/cvert-ops/internal/store"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// ── Request / response types ────────────────────────────────────────────────────

type nlSearchRequest struct {
	Query string `json:"query"`
}

type nlSearchResponse struct {
	InterpretedQuery json.RawMessage `json:"interpreted_query"`
	Results          []CVEItem       `json:"results"`
	NextCursor       string          `json:"next_cursor,omitempty"`
	Model            string          `json:"model"`
	Cached           bool            `json:"cached"`
}

type summarizeResponse struct {
	CVEID   string `json:"cve_id"`
	Summary string `json:"summary"`
	Model   string `json:"model"`
	Cached  bool   `json:"cached"`
}

// ── NL Search Handler ───────────────────────────────────────────────────────────

// nlSearchHandler handles POST /api/v1/orgs/{org_id}/ai/nl-search.
// Translates a natural language query to DSL via the LLM, executes it, and
// returns matching CVEs.
func (srv *Server) nlSearchHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	if srv.llm == nil {
		http.Error(w, "AI features not configured", http.StatusServiceUnavailable)
		return
	}

	// Parse request body.
	var req nlSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate query.
	query := strings.TrimSpace(req.Query)
	if query == "" {
		http.Error(w, "query must not be empty", http.StatusUnprocessableEntity)
		return
	}
	if len(query) > 1000 {
		http.Error(w, "query must not exceed 1000 characters", http.StatusUnprocessableEntity)
		return
	}

	// Parse pagination params from query string.
	cursor := r.URL.Query().Get("cursor")
	limit := parseIntParam(r.URL.Query().Get("limit"), 25, 1, 100)

	// Compute input hash for caching.
	inputHash := fmt.Sprintf("%x", sha256.Sum256([]byte(query)))

	const feature = "nl_search"
	promptVersion := ai.PromptVersion()

	// Quota check.
	if srv.cfg.AIQuotaEnabled {
		count, err := srv.store.IncrementAIUsage(r.Context(), orgID, feature)
		if err != nil {
			slog.ErrorContext(r.Context(), "ai: increment usage", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		dailyLimit := srv.resolveAIQuotaLimit(r.Context(), orgID, feature, ai.TierLimits{
			Free:       srv.cfg.AINLSearchLimitFree,
			Pro:        srv.cfg.AINLSearchLimitPro,
			Enterprise: srv.cfg.AINLSearchLimitEnterprise,
		})
		if count > dailyLimit {
			metrics.AIQuotaDenialsTotal.WithLabelValues(feature).Inc()
			w.Header().Set("Retry-After", retryAfterMidnight())
			http.Error(w, "daily AI quota exceeded", http.StatusTooManyRequests)
			return
		}
	}

	// Cache check.
	var queryJSON json.RawMessage
	var inputTokens, outputTokens int
	cached := false

	cachedResp, hit, err := srv.store.GetAICache(r.Context(), orgID, feature, promptVersion, inputHash)
	if err != nil {
		slog.ErrorContext(r.Context(), "ai: cache get", "error", err)
		// Non-fatal — proceed without cache.
	}
	if hit {
		metrics.AICacheHitsTotal.WithLabelValues(feature).Inc()
		queryJSON = cachedResp
		cached = true
	} else {
		metrics.AICacheMissesTotal.WithLabelValues(feature).Inc()

		// Call LLM.
		result, llmErr := srv.llm.GenerateStructuredQuery(r.Context(), query)
		if llmErr != nil {
			slog.ErrorContext(r.Context(), "ai: llm generate", "error", llmErr)
			// Decrement quota on infrastructure failure.
			if decErr := srv.store.DecrementAIUsage(r.Context(), orgID, feature); decErr != nil {
				slog.ErrorContext(r.Context(), "ai: decrement usage after failure", "error", decErr)
			}
			srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, false, 0, 0, start, "error", "llm_failure")
			metrics.AIRequestsTotal.WithLabelValues(feature, "error").Inc()
			http.Error(w, "AI service unavailable", http.StatusServiceUnavailable)
			return
		}

		queryJSON = result.QueryJSON
		inputTokens = result.InputTokens
		outputTokens = result.OutputTokens

		// Update token counts.
		if err := srv.store.UpdateAIUsageTokens(r.Context(), orgID, feature, inputTokens, outputTokens); err != nil {
			slog.ErrorContext(r.Context(), "ai: update tokens", "error", err)
		}
		metrics.AITokensTotal.WithLabelValues(feature, "input").Add(float64(inputTokens))
		metrics.AITokensTotal.WithLabelValues(feature, "output").Add(float64(outputTokens))

		// Write to cache.
		if err := srv.store.PutAICache(r.Context(), orgID, feature, promptVersion, inputHash, queryJSON, srv.cfg.AICacheNLSearchTTL); err != nil {
			slog.ErrorContext(r.Context(), "ai: cache put", "error", err)
		}
	}

	// Parse, validate, and compile the DSL.
	rule, parseErr := dsl.Parse(queryJSON)
	if parseErr != nil {
		slog.ErrorContext(r.Context(), "ai: dsl parse", "error", parseErr, "query_json", truncateForLog(string(queryJSON), 500))
		srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, cached, 0, 0, start, "error", "dsl_parse")
		metrics.AIRequestsTotal.WithLabelValues(feature, "error").Inc()
		http.Error(w, "AI returned invalid query structure", http.StatusBadGateway)
		return
	}

	valErrs, _, _ := dsl.Validate(rule, false)
	if hasBlockingErrors(valErrs) {
		slog.ErrorContext(r.Context(), "ai: dsl validation failed", "errors", valErrs, "query_json", truncateForLog(string(queryJSON), 500))
		srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, cached, 0, 0, start, "error", "dsl_validate")
		metrics.AIRequestsTotal.WithLabelValues(feature, "error").Inc()
		http.Error(w, "AI returned invalid query", http.StatusBadGateway)
		return
	}

	compiled, compileErr := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
	if compileErr != nil {
		slog.ErrorContext(r.Context(), "ai: dsl compile", "error", compileErr)
		srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, cached, 0, 0, start, "error", "dsl_compile")
		metrics.AIRequestsTotal.WithLabelValues(feature, "error").Inc()
		http.Error(w, "AI returned invalid query", http.StatusBadGateway)
		return
	}

	// Execute DSL query.
	results, nextCursor, execErr := srv.store.ExecuteDSLQuery(r.Context(), compiled, cursor, limit)
	if execErr != nil {
		slog.ErrorContext(r.Context(), "ai: execute dsl query", "error", execErr)
		srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, cached, 0, 0, start, "error", "query_exec")
		metrics.AIRequestsTotal.WithLabelValues(feature, "error").Inc()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Convert to API items.
	items := make([]CVEItem, len(results))
	for i, c := range results {
		items[i] = cfeToItem(c)
	}

	// Log and respond.
	srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, cached, inputTokens, outputTokens, start, "success", "")
	metrics.AIRequestsTotal.WithLabelValues(feature, "ok").Inc()
	metrics.AIRequestDuration.WithLabelValues(feature).Observe(time.Since(start).Seconds())

	writeJSON(w, http.StatusOK, nlSearchResponse{
		InterpretedQuery: queryJSON,
		Results:          items,
		NextCursor:       nextCursor,
		Model:            srv.cfg.GeminiModel,
		Cached:           cached,
	})
}

// ── Summarize Handler ───────────────────────────────────────────────────────────

// summarizeHandler handles POST /api/v1/orgs/{org_id}/ai/summarize/{cve_id}.
// Generates a concise summary of a CVE using the LLM.
func (srv *Server) summarizeHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	if srv.llm == nil {
		http.Error(w, "AI features not configured", http.StatusServiceUnavailable)
		return
	}

	cveID := chi.URLParam(r, "cve_id")
	if cveID == "" {
		http.Error(w, "cve_id is required", http.StatusBadRequest)
		return
	}
	if !isValidCVEID(cveID) {
		http.Error(w, "invalid cve_id format", http.StatusBadRequest)
		return
	}

	const feature = "summarize"
	promptVersion := ai.PromptVersion()

	// Quota check.
	if srv.cfg.AIQuotaEnabled {
		count, err := srv.store.IncrementAIUsage(r.Context(), orgID, feature)
		if err != nil {
			slog.ErrorContext(r.Context(), "ai: increment usage", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		dailyLimit := srv.resolveAIQuotaLimit(r.Context(), orgID, feature, ai.TierLimits{
			Free:       srv.cfg.AISummarizeLimitFree,
			Pro:        srv.cfg.AISummarizeLimitPro,
			Enterprise: srv.cfg.AISummarizeLimitEnterprise,
		})
		if count > dailyLimit {
			metrics.AIQuotaDenialsTotal.WithLabelValues(feature).Inc()
			w.Header().Set("Retry-After", retryAfterMidnight())
			http.Error(w, "daily AI quota exceeded", http.StatusTooManyRequests)
			return
		}
	}

	// Fetch CVE.
	cve, err := srv.store.GetCVE(r.Context(), cveID)
	if err != nil {
		slog.ErrorContext(r.Context(), "ai: get cve", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if cve == nil {
		http.Error(w, "CVE not found", http.StatusNotFound)
		return
	}

	// Build input hash from CVE ID + material hash for cache key stability.
	materialHash := ""
	if cve.MaterialHash.Valid {
		materialHash = cve.MaterialHash.String
	}
	inputHash := fmt.Sprintf("%x", sha256.Sum256([]byte(cveID+materialHash)))

	// Cache check.
	var summary string
	var inputTokens, outputTokens int
	cached := false

	cachedResp, hit, err := srv.store.GetAICache(r.Context(), orgID, feature, promptVersion, inputHash)
	if err != nil {
		slog.ErrorContext(r.Context(), "ai: cache get", "error", err)
	}
	if hit {
		metrics.AICacheHitsTotal.WithLabelValues(feature).Inc()
		// Cached response is the summary string as JSON.
		var cachedSummary string
		if err := json.Unmarshal(cachedResp, &cachedSummary); err != nil {
			slog.ErrorContext(r.Context(), "ai: unmarshal cached summary", "error", err)
			// Fall through to LLM call.
		} else {
			summary = cachedSummary
			cached = true
		}
	}

	if !cached {
		metrics.AICacheMissesTotal.WithLabelValues(feature).Inc()

		// Build CVESummaryInput.
		input := buildSummaryInput(cve)

		// Call LLM.
		result, llmErr := srv.llm.Summarize(r.Context(), input)
		if llmErr != nil {
			slog.ErrorContext(r.Context(), "ai: llm summarize", "error", llmErr)
			if decErr := srv.store.DecrementAIUsage(r.Context(), orgID, feature); decErr != nil {
				slog.ErrorContext(r.Context(), "ai: decrement usage after failure", "error", decErr)
			}
			srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, false, 0, 0, start, "error", "llm_failure")
			metrics.AIRequestsTotal.WithLabelValues(feature, "error").Inc()
			http.Error(w, "AI service unavailable", http.StatusServiceUnavailable)
			return
		}

		summary = result.Summary
		inputTokens = result.InputTokens
		outputTokens = result.OutputTokens

		// Update token counts.
		if err := srv.store.UpdateAIUsageTokens(r.Context(), orgID, feature, inputTokens, outputTokens); err != nil {
			slog.ErrorContext(r.Context(), "ai: update tokens", "error", err)
		}
		metrics.AITokensTotal.WithLabelValues(feature, "input").Add(float64(inputTokens))
		metrics.AITokensTotal.WithLabelValues(feature, "output").Add(float64(outputTokens))

		// Write to cache (store summary as JSON string).
		summaryJSON, _ := json.Marshal(summary)
		if err := srv.store.PutAICache(r.Context(), orgID, feature, promptVersion, inputHash, summaryJSON, srv.cfg.AICacheSummarizeTTL); err != nil {
			slog.ErrorContext(r.Context(), "ai: cache put", "error", err)
		}
	}

	// Log and respond.
	srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, cached, inputTokens, outputTokens, start, "success", "")
	metrics.AIRequestsTotal.WithLabelValues(feature, "ok").Inc()
	metrics.AIRequestDuration.WithLabelValues(feature).Observe(time.Since(start).Seconds())

	writeJSON(w, http.StatusOK, summarizeResponse{
		CVEID:   cveID,
		Summary: summary,
		Model:   srv.cfg.GeminiModel,
		Cached:  cached,
	})
}

// ── Helpers ─────────────────────────────────────────────────────────────────────

// resolveAIQuotaLimit fetches any per-org override and resolves the effective
// daily limit using the tier hierarchy.
func (srv *Server) resolveAIQuotaLimit(ctx context.Context, orgID uuid.UUID, feature string, tierLimits ai.TierLimits) int {
	override, hasOverride, err := srv.store.GetAIQuotaOverride(ctx, orgID, feature)
	if err != nil {
		slog.ErrorContext(ctx, "ai: get quota override", "error", err)
		// Fall through to tier default.
	}
	// No org tier column yet — all orgs default to "free".
	return ai.ResolveLimit(override, hasOverride, tierLimits, "free")
}

// logAIRequest records an AI request to the request log table.
func (srv *Server) logAIRequest(r *http.Request, orgID, userID uuid.UUID, feature, inputHash, promptVersion string, cacheHit bool, inputTokens, outputTokens int, start time.Time, status, errorType string) {
	latency := time.Since(start).Milliseconds()
	if err := srv.store.InsertAIRequestLog(r.Context(), store.AIRequestLogEntry{
		OrgID:         orgID,
		UserID:        userID,
		Feature:       feature,
		InputHash:     inputHash,
		PromptVersion: promptVersion,
		Model:         srv.cfg.GeminiModel,
		CacheHit:      cacheHit,
		InputTokens:   inputTokens,
		OutputTokens:  outputTokens,
		LatencyMS:     int(latency), //nolint:gosec // G115: latency in ms fits int
		Status:        status,
		ErrorType:     errorType,
	}); err != nil {
		slog.ErrorContext(r.Context(), "ai: log request", "error", err)
	}
}

// buildSummaryInput constructs a CVESummaryInput from a Cfe row.
func buildSummaryInput(cve *generated.Cfe) ai.CVESummaryInput {
	input := ai.CVESummaryInput{
		CVEID:            cve.CveID,
		ExploitAvailable: cve.ExploitAvailable,
		InCISAKEV:        cve.InCisaKev,
	}
	if cve.Severity.Valid {
		input.Severity = cve.Severity.String
	}
	if cve.DescriptionPrimary.Valid {
		input.Description = ai.Sanitize(cve.DescriptionPrimary.String)
	}
	if cve.CvssV3Score.Valid {
		input.CVSSV3Score = &cve.CvssV3Score.Float64
	}
	if cve.CvssV4Score.Valid {
		input.CVSSV4Score = &cve.CvssV4Score.Float64
	}
	if cve.EpssScore.Valid {
		input.EPSSScore = &cve.EpssScore.Float64
	}
	if len(cve.CweIds) > 0 {
		input.CWEIDs = cve.CweIds
	}
	return input
}

// cveIDPattern matches standard CVE identifiers (CVE-YYYY-NNNNN+).
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// isValidCVEID checks whether s is a well-formed CVE identifier.
func isValidCVEID(s string) bool {
	return cveIDPattern.MatchString(s)
}

// truncateForLog returns s truncated to maxLen characters for safe logging.
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}

// parseIntParam parses an integer query parameter with bounds clamping.
func parseIntParam(s string, defaultVal, min, max int) int {
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// retryAfterMidnight returns the number of seconds until the next UTC midnight
// as a string, suitable for the Retry-After header.
func retryAfterMidnight() string {
	now := time.Now().UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	secs := int(midnight.Sub(now).Seconds())
	if secs <= 0 {
		secs = 1
	}
	return strconv.Itoa(secs)
}
