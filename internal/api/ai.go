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

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/ai"
	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/metrics"
	"github.com/scarson/cvert-ops/internal/store"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
	"github.com/scarson/cvert-ops/internal/tier"
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
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	if srv.llm == nil {
		writeProblem(w, http.StatusServiceUnavailable, "AI features not configured")
		return
	}

	// Parse request body.
	var req nlSearchRequest
	if detail := decodeJSON(r, &req); detail != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", detail)
		return
	}

	// Validate query.
	query := strings.TrimSpace(req.Query)
	if query == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "query must not be empty", Location: "body.query"})
		return
	}
	if len(query) > 1000 {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "query must not exceed 1000 characters", Location: "body.query"})
		return
	}

	// Parse pagination params from query string.
	cursor := r.URL.Query().Get("cursor")
	limit, ok2 := parseLimitParam(w, r, 25, 100)
	if !ok2 {
		return
	}

	// Compute input hash for caching.
	inputHash := fmt.Sprintf("%x", sha256.Sum256([]byte(query)))

	const feature = "nl_search"
	promptVersion := ai.PromptVersion()

	// Cache check (before quota — cache hits don't cost LLM API calls).
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

		// Quota check (only on cache miss — cache hits are free).
		if srv.cfg.AIQuotaEnabled {
			count, qErr := srv.store.IncrementAIUsage(r.Context(), orgID, feature)
			if qErr != nil {
				slog.ErrorContext(r.Context(), "ai: increment usage", "error", qErr)
				writeProblem(w, http.StatusInternalServerError, "internal error")
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
				writeProblem(w, http.StatusTooManyRequests, "daily AI quota exceeded")
				return
			}
		}

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
			writeProblem(w, http.StatusServiceUnavailable, "AI service unavailable")
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
		writeProblem(w, http.StatusBadGateway, "AI returned invalid query structure")
		return
	}

	valErrs, _, _ := dsl.Validate(rule, false)
	if hasBlockingErrors(valErrs) {
		slog.ErrorContext(r.Context(), "ai: dsl validation failed", "errors", valErrs, "query_json", truncateForLog(string(queryJSON), 500))
		srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, cached, 0, 0, start, "error", "dsl_validate")
		metrics.AIRequestsTotal.WithLabelValues(feature, "error").Inc()
		writeProblem(w, http.StatusBadGateway, "AI returned invalid query")
		return
	}

	compiled, compileErr := dsl.Compile(rule, uuid.Nil, 0, uuid.Nil, nil)
	if compileErr != nil {
		slog.ErrorContext(r.Context(), "ai: dsl compile", "error", compileErr)
		srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, cached, 0, 0, start, "error", "dsl_compile")
		metrics.AIRequestsTotal.WithLabelValues(feature, "error").Inc()
		writeProblem(w, http.StatusBadGateway, "AI returned invalid query")
		return
	}

	// Execute DSL query.
	results, nextCursor, execErr := srv.store.ExecuteDSLQuery(r.Context(), compiled, cursor, limit)
	if execErr != nil {
		slog.ErrorContext(r.Context(), "ai: execute dsl query", "error", execErr)
		srv.logAIRequest(r, orgID, userID, feature, inputHash, promptVersion, cached, 0, 0, start, "error", "query_exec")
		metrics.AIRequestsTotal.WithLabelValues(feature, "error").Inc()
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Convert to API items.
	items := make([]CVEItem, len(results))
	for i, c := range results {
		items[i] = cveToItem(c)
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
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	userID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	if srv.llm == nil {
		writeProblem(w, http.StatusServiceUnavailable, "AI features not configured")
		return
	}

	cveID := chi.URLParam(r, "cve_id")
	if cveID == "" {
		writeProblem(w, http.StatusBadRequest, "cve_id is required")
		return
	}
	if !isValidCVEID(cveID) {
		writeProblem(w, http.StatusBadRequest, "invalid cve_id format")
		return
	}

	const feature = "summarize"
	promptVersion := ai.PromptVersion()

	// Fetch CVE.
	cve, err := srv.store.GetCVE(r.Context(), cveID)
	if err != nil {
		slog.ErrorContext(r.Context(), "ai: get cve", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if cve == nil {
		writeProblem(w, http.StatusNotFound, "CVE not found")
		return
	}

	// Build input hash from CVE ID + material hash for cache key stability.
	materialHash := ""
	if cve.MaterialHash.Valid {
		materialHash = cve.MaterialHash.String
	}
	inputHash := fmt.Sprintf("%x", sha256.Sum256([]byte(cveID+materialHash)))

	// Cache check (before quota — cache hits don't cost LLM API calls).
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

		// Quota check (only on cache miss — cache hits are free).
		if srv.cfg.AIQuotaEnabled {
			count, qErr := srv.store.IncrementAIUsage(r.Context(), orgID, feature)
			if qErr != nil {
				slog.ErrorContext(r.Context(), "ai: increment usage", "error", qErr)
				writeProblem(w, http.StatusInternalServerError, "internal error")
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
				writeProblem(w, http.StatusTooManyRequests, "daily AI quota exceeded")
				return
			}
		}

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
			writeProblem(w, http.StatusServiceUnavailable, "AI service unavailable")
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
	orgTier := "free"
	if resolver, ok := ctx.Value(ctxTierResolver).(*tier.Resolver); ok {
		orgTier = resolver.Tier
	}
	return ai.ResolveLimit(override, hasOverride, tierLimits, orgTier)
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

// buildSummaryInput constructs a CVESummaryInput from a CVE row.
func buildSummaryInput(cve *generated.CVE) ai.CVESummaryInput {
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
