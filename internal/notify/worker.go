// ABOUTME: Delivery worker: polls notification_deliveries, dispatches to webhook or email.
// ABOUTME: Per-org semaphore caps concurrent deliveries. sync.WaitGroup for graceful shutdown.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/metrics"
	"github.com/scarson/cvert-ops/internal/store"
)

// WorkerConfig holds delivery worker tuning parameters (sourced from config.Config).
type WorkerConfig struct {
	ClaimBatchSize      int
	MaxAttempts         int
	BackoffBaseSeconds  int
	MaxConcurrentPerOrg int
	StuckThreshold      time.Duration // default 2 minutes if zero
	RetentionEnabled    bool          // gate for retention job scheduling
}

// Worker polls notification_deliveries and executes outbound deliveries (webhook or email).
type Worker struct {
	store        *store.Store
	client       *http.Client
	cfg          WorkerConfig
	smtpCfg      SmtpConfig
	externalURL  string
	log          *slog.Logger
	sems         map[uuid.UUID]chan struct{} // per-org semaphores, lazy-init
	semsLastUsed map[uuid.UUID]time.Time    // last use time per org semaphore
	semsMu       sync.Mutex
	wg           sync.WaitGroup
	dispatcher   *Dispatcher
	lastClaimAt  atomic.Value // stores time.Time; zero value means never started
}

// NewWorker creates a Worker. client should be the production safeurl-wrapped client.
func NewWorker(st *store.Store, client *http.Client, cfg WorkerConfig, smtpCfg SmtpConfig, externalURL string) *Worker {
	if cfg.StuckThreshold == 0 {
		cfg.StuckThreshold = 2 * time.Minute
	}
	return &Worker{
		store:        st,
		client:       client,
		cfg:          cfg,
		smtpCfg:      smtpCfg,
		externalURL:  externalURL,
		log:          slog.Default(),
		sems:         make(map[uuid.UUID]chan struct{}),
		semsLastUsed: make(map[uuid.UUID]time.Time),
	}
}

// SetDispatcher injects the Dispatcher used by the orphaned-event recovery ticker.
func (w *Worker) SetDispatcher(d *Dispatcher) {
	w.dispatcher = d
}

// Start runs the worker until ctx is cancelled.
func (w *Worker) Start(ctx context.Context) {
	w.lastClaimAt.Store(time.Now()) // mark alive for /readyz before first tick
	claimTicker := time.NewTicker(5 * time.Second)
	stuckTicker := time.NewTicker(60 * time.Second)
	recoveryTicker := time.NewTicker(5 * time.Minute)
	digestTicker := time.NewTicker(60 * time.Second)
	retentionTicker := time.NewTicker(24 * time.Hour)
	evictTicker := time.NewTicker(semaphoreEvictionAge)
	defer claimTicker.Stop()
	defer stuckTicker.Stop()
	defer recoveryTicker.Stop()
	defer digestTicker.Stop()
	defer retentionTicker.Stop()
	defer evictTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.wg.Wait()
			return
		case <-claimTicker.C:
			// Update health timestamp BEFORE runClaim — runClaim can block on
			// per-org semaphore acquisition, which would make Healthy() return
			// false even though the event loop is alive.
			w.lastClaimAt.Store(time.Now())
			w.runClaim(ctx)
		case <-stuckTicker.C:
			w.runStuckReset(ctx)
		case <-recoveryTicker.C:
			w.runRecovery(ctx)
		case <-digestTicker.C:
			w.runDigest(ctx)
		case <-retentionTicker.C:
			w.scheduleRetention(ctx)
		case <-evictTicker.C:
			w.evictStaleSemaphores()
		}
	}
}

// Healthy reports whether the delivery worker's claim loop is running.
// Returns false if the worker has never ticked or the last tick is stale.
func (w *Worker) Healthy() bool {
	v := w.lastClaimAt.Load()
	if v == nil {
		return false
	}
	lastTick := v.(time.Time)
	return time.Since(lastTick) < 2*5*time.Second // 2x claim interval (5s)
}

// RunOnce executes one claim tick and waits for all goroutines to finish. Used in tests only.
func (w *Worker) RunOnce(ctx context.Context) {
	w.runClaim(ctx)
	w.wg.Wait()
}

// RunRetentionScheduleOnce executes a single retention scheduling tick. Used in tests only.
func (w *Worker) RunRetentionScheduleOnce(ctx context.Context) {
	w.scheduleRetention(ctx)
}

// RunStuckResetOnce executes a single stuck-delivery reset tick. Used in tests only.
func (w *Worker) RunStuckResetOnce(ctx context.Context) {
	w.runStuckReset(ctx)
}

// RunRecoveryOnce executes a single orphaned-event recovery tick. Used in tests only.
func (w *Worker) RunRecoveryOnce(ctx context.Context) {
	w.runRecovery(ctx)
}

// RunDigestOnce executes a single digest tick. Used in tests only.
func (w *Worker) RunDigestOnce(ctx context.Context) {
	w.runDigest(ctx)
}

func (w *Worker) runClaim(ctx context.Context) {
	// ClaimPendingDeliveries atomically claims and marks rows as processing.
	rows, err := w.store.ClaimPendingDeliveries(ctx, w.cfg.ClaimBatchSize)
	if err != nil {
		w.log.Error("claim pending deliveries", "err", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	// Detach from parent context so in-flight deliveries survive shutdown.
	// The worker's wg.Wait() in Start() ensures graceful completion.
	detached := context.WithoutCancel(ctx)

	for _, row := range rows {
		row := row
		sem := w.semaphore(row.OrgID)
		sem <- struct{}{} // blocking: intentional — bounded by delivery timeout and stuck-reset recovery
		w.wg.Add(1)
		go func() {
			defer func() { <-sem }()
			defer w.wg.Done()
			w.deliver(detached, row)
		}()
	}
}

func (w *Worker) deliver(ctx context.Context, row store.ClaimedDelivery) {
	start := time.Now()
	ch, err := w.store.GetNotificationChannelForDelivery(ctx, row.ChannelID)
	if err != nil || ch == nil {
		msg := "channel lookup failed"
		if err != nil {
			msg = fmt.Sprintf("channel lookup failed: %v", err)
		}
		w.log.Error("get channel for delivery", "channel_id", row.ChannelID, "err", err)
		w.exhaust(ctx, row.ID, msg)
		metrics.NotificationDeliveriesTotal.WithLabelValues("unknown", "failure").Inc()
		metrics.NotificationDeliveryDuration.WithLabelValues("unknown").Observe(time.Since(start).Seconds())
		return
	}

	var sendErr error
	switch ch.Type {
	case "webhook":
		sendErr = w.deliverWebhook(ctx, row, ch)
	case "email":
		sendErr = w.deliverEmail(ctx, row, ch)
	default:
		w.exhaust(ctx, row.ID, fmt.Sprintf("unsupported channel type: %s", ch.Type))
		metrics.NotificationDeliveriesTotal.WithLabelValues(ch.Type, "failure").Inc()
		metrics.NotificationDeliveryDuration.WithLabelValues(ch.Type).Observe(time.Since(start).Seconds())
		return
	}

	if sendErr == nil {
		if err := w.store.CompleteDelivery(ctx, row.ID); err != nil {
			w.log.Error("complete delivery", "id", row.ID, "err", err)
		}
		metrics.NotificationDeliveriesTotal.WithLabelValues(ch.Type, "success").Inc()
		metrics.NotificationDeliveryDuration.WithLabelValues(ch.Type).Observe(time.Since(start).Seconds())
		return
	}

	// Permanent errors should exhaust immediately — retrying will never help.
	if isPermanentDeliveryError(sendErr) {
		w.log.Warn("permanent delivery failure", "id", row.ID, "type", ch.Type, "err", sendErr)
		w.exhaust(ctx, row.ID, sendErr.Error())
		metrics.NotificationDeliveriesTotal.WithLabelValues(ch.Type, "exhausted").Inc()
		metrics.NotificationDeliveryDuration.WithLabelValues(ch.Type).Observe(time.Since(start).Seconds())
		return
	}

	nextAttempt := int(row.AttemptCount) + 1
	w.log.Warn("delivery failed", "id", row.ID, "type", ch.Type, "err", sendErr, "attempt", nextAttempt)
	if nextAttempt >= w.cfg.MaxAttempts {
		w.exhaust(ctx, row.ID, sendErr.Error())
		metrics.NotificationDeliveriesTotal.WithLabelValues(ch.Type, "exhausted").Inc()
		metrics.NotificationDeliveryDuration.WithLabelValues(ch.Type).Observe(time.Since(start).Seconds())
		return
	}

	backoff := w.backoffSeconds(nextAttempt)
	if err := w.store.RetryDelivery(ctx, row.ID, backoff, sendErr.Error()); err != nil {
		w.log.Error("retry delivery", "id", row.ID, "err", err)
	}

	// Record metrics AFTER DB writes (tp§9.6).
	metrics.NotificationDeliveriesTotal.WithLabelValues(ch.Type, "failure").Inc()
	metrics.NotificationDeliveryDuration.WithLabelValues(ch.Type).Observe(time.Since(start).Seconds())
}

func (w *Worker) deliverWebhook(ctx context.Context, row store.ClaimedDelivery, ch *store.NotificationChannelForDeliveryRow) error {
	var config struct {
		URL           string            `json:"url"`
		CustomHeaders map[string]string `json:"custom_headers"`
	}
	_ = json.Unmarshal(ch.Config, &config) //nolint:errcheck // empty URL on bad JSON causes Send to fail → retry/exhaust handles it

	return Send(ctx, w.client, WebhookConfig{
		URL:                    config.URL,
		SigningSecret:          ch.SigningSecret.String,
		SigningSecretSecondary: ch.SigningSecretSecondary.String,
		CustomHeaders:          config.CustomHeaders,
	}, row.Payload)
}

func (w *Worker) deliverEmail(ctx context.Context, row store.ClaimedDelivery, ch *store.NotificationChannelForDeliveryRow) error {
	// Parse channel config for recipients. Config errors are permanent — the
	// channel data won't change between retries.
	var emailCfg struct {
		Recipients []string `json:"recipients"`
	}
	if err := json.Unmarshal(ch.Config, &emailCfg); err != nil {
		return &permanentDeliveryError{err: fmt.Errorf("parse email config: %w", err)}
	}
	if len(emailCfg.Recipients) == 0 {
		return &permanentDeliveryError{err: fmt.Errorf("email channel has no recipients")}
	}

	// Deserialize payload into CVE snapshots.
	var snaps []cveSnapshot
	if err := json.Unmarshal(row.Payload, &snaps); err != nil {
		return fmt.Errorf("unmarshal delivery payload: %w", err)
	}

	summaries := snapshotsToCVESummaries(snaps, w.externalURL)

	var subject, htmlBody, textBody string
	var renderErr error

	switch row.Kind {
	case "alert":
		ruleName := "Alert Rule"
		if row.RuleID.Valid {
			if name, err := w.store.GetAlertRuleName(ctx, row.RuleID.UUID); err == nil && name != "" {
				ruleName = name
			}
		}
		ruleID := ""
		if row.RuleID.Valid {
			ruleID = row.RuleID.UUID.String()
		}
		subject, htmlBody, textBody, renderErr = RenderAlert(AlertTemplateData{
			RuleName:    ruleName,
			RuleID:      ruleID,
			CVEs:        summaries,
			CVErtOpsURL: w.externalURL,
		})
	case "digest":
		reportName := "Digest Report"
		if row.ReportID.Valid {
			if name, err := w.store.GetScheduledReportName(ctx, row.ReportID.UUID); err == nil && name != "" {
				reportName = name
			}
		}
		orgName := "Organization"
		if org, err := w.store.GetOrgByID(ctx, row.OrgID); err == nil && org != nil {
			orgName = org.Name
		}
		totalCount := len(summaries)
		truncated := totalCount > 25
		if truncated {
			summaries = summaries[:25]
		}
		subject, htmlBody, textBody, renderErr = RenderDigest(DigestTemplateData{
			OrgName:     orgName,
			ReportName:  reportName,
			Date:        time.Now().UTC().Format("2006-01-02"),
			CVEs:        summaries,
			TotalCount:  totalCount,
			Truncated:   truncated,
			ViewAllURL:  w.externalURL,
			CVErtOpsURL: w.externalURL,
		})
	default:
		return &permanentDeliveryError{err: fmt.Errorf("unsupported delivery kind for email: %s", row.Kind)}
	}
	if renderErr != nil {
		return fmt.Errorf("render email template: %w", renderErr)
	}

	return EmailSend(ctx, w.smtpCfg, emailCfg.Recipients, subject, htmlBody, textBody)
}

// permanentDeliveryError wraps errors that should never be retried (config
// parse failures, missing recipients, SMTP 5xx, etc.).
type permanentDeliveryError struct {
	err error
}

func (e *permanentDeliveryError) Error() string { return e.err.Error() }
func (e *permanentDeliveryError) Unwrap() error { return e.err }

// isPermanentDeliveryError returns true if the error is known to be permanent
// and retrying will never succeed. Covers both Go-level config errors (wrapped
// with permanentDeliveryError) and SMTP 5xx responses.
func isPermanentDeliveryError(err error) bool {
	if err == nil {
		return false
	}
	var pe *permanentDeliveryError
	if errors.As(err, &pe) {
		return true
	}
	// SMTP 5xx codes indicate permanent failures (mailbox doesn't exist, relay denied, etc.).
	msg := err.Error()
	for _, code := range []string{"550 ", "551 ", "552 ", "553 ", "554 ", "555 "} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

func (w *Worker) exhaust(ctx context.Context, id uuid.UUID, lastError string) {
	if err := w.store.ExhaustDelivery(ctx, id, lastError); err != nil {
		w.log.Error("exhaust delivery", "id", id, "err", err)
	}
}

func (w *Worker) backoffSeconds(attempt int) int {
	base := float64(w.cfg.BackoffBaseSeconds)
	delay := base * math.Pow(2, float64(attempt-1))
	jitter := 0.5 + rand.Float64() //nolint:gosec // G404: jitter for backoff is not a security-sensitive operation
	return int(delay * jitter)
}

func (w *Worker) semaphore(orgID uuid.UUID) chan struct{} {
	w.semsMu.Lock()
	defer w.semsMu.Unlock()
	if _, ok := w.sems[orgID]; !ok {
		w.sems[orgID] = make(chan struct{}, w.cfg.MaxConcurrentPerOrg)
	}
	w.semsLastUsed[orgID] = time.Now()
	return w.sems[orgID]
}

const semaphoreEvictionAge = 10 * time.Minute

func (w *Worker) evictStaleSemaphores() {
	w.semsMu.Lock()
	defer w.semsMu.Unlock()
	cutoff := time.Now().Add(-semaphoreEvictionAge)
	for orgID, lastUsed := range w.semsLastUsed {
		if lastUsed.Before(cutoff) && len(w.sems[orgID]) == 0 {
			delete(w.sems, orgID)
			delete(w.semsLastUsed, orgID)
		}
	}
}

func (w *Worker) runStuckReset(ctx context.Context) {
	if err := w.store.ResetStuckDeliveries(ctx, w.cfg.StuckThreshold); err != nil {
		w.log.Error("reset stuck deliveries", "err", err)
	}
}

func (w *Worker) runRecovery(ctx context.Context) {
	if w.dispatcher == nil {
		return
	}
	rows, err := w.store.OrphanedAlertEvents(ctx, 100)
	if err != nil {
		w.log.Error("orphaned event scan", "err", err)
		return
	}
	for _, row := range rows {
		if err := w.dispatcher.Fanout(ctx, row.OrgID, row.RuleID, row.CveID); err != nil {
			w.log.Error("recovery fanout", "rule_id", row.RuleID, "cve_id", row.CveID, "err", err)
		}
	}
}

func (w *Worker) scheduleRetention(ctx context.Context) {
	if !w.cfg.RetentionEnabled {
		return
	}

	has, err := w.store.HasPendingOrRunningJob(ctx, "cleanup:retention")
	if err != nil {
		w.log.Error("check pending retention job", "err", err)
		return
	}
	if has {
		w.log.Debug("retention job already pending/running, skipping")
		return
	}

	lockKey := "cleanup:retention"
	_, err = w.store.EnqueueJob(ctx, "retention_cleanup", 0, json.RawMessage(`{}`), &lockKey, 1, nil)
	if err != nil {
		w.log.Error("enqueue retention job", "err", err)
		return
	}
	w.log.Info("enqueued retention cleanup job")
}
