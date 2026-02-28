// ABOUTME: Delivery worker: polls notification_deliveries, claims rows, executes webhooks.
// ABOUTME: Per-org semaphore caps concurrent deliveries. sync.WaitGroup for graceful shutdown.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
)

// WorkerConfig holds delivery worker tuning parameters (sourced from config.Config).
type WorkerConfig struct {
	ClaimBatchSize      int
	MaxAttempts         int
	BackoffBaseSeconds  int
	MaxConcurrentPerOrg int
	StuckThreshold      time.Duration // default 2 minutes if zero
}

// Worker polls notification_deliveries and executes outbound HTTP webhook deliveries.
type Worker struct {
	store      *store.Store
	client     *http.Client
	cfg        WorkerConfig
	log        *slog.Logger
	sems       map[uuid.UUID]chan struct{} // per-org semaphores, lazy-init
	semsMu     sync.Mutex
	wg         sync.WaitGroup
	dispatcher *Dispatcher
}

// NewWorker creates a Worker. client should be the production safeurl-wrapped client.
func NewWorker(st *store.Store, client *http.Client, cfg WorkerConfig) *Worker {
	if cfg.StuckThreshold == 0 {
		cfg.StuckThreshold = 2 * time.Minute
	}
	return &Worker{
		store:  st,
		client: client,
		cfg:    cfg,
		log:    slog.Default(),
		sems:   make(map[uuid.UUID]chan struct{}),
	}
}

// SetDispatcher injects the Dispatcher used by the orphaned-event recovery ticker.
func (w *Worker) SetDispatcher(d *Dispatcher) {
	w.dispatcher = d
}

// Start runs the worker until ctx is cancelled.
func (w *Worker) Start(ctx context.Context) {
	claimTicker := time.NewTicker(5 * time.Second)
	stuckTicker := time.NewTicker(60 * time.Second)
	recoveryTicker := time.NewTicker(5 * time.Minute)
	defer claimTicker.Stop()
	defer stuckTicker.Stop()
	defer recoveryTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.wg.Wait()
			return
		case <-claimTicker.C:
			w.runClaim(ctx)
		case <-stuckTicker.C:
			w.runStuckReset(ctx)
		case <-recoveryTicker.C:
			w.runRecovery(ctx)
		}
	}
}

// RunOnce executes one claim tick and waits for all goroutines to finish. Used in tests only.
func (w *Worker) RunOnce(ctx context.Context) {
	w.runClaim(ctx)
	w.wg.Wait()
}

func (w *Worker) runClaim(ctx context.Context) {
	rows, err := w.store.ClaimPendingDeliveries(ctx, w.cfg.ClaimBatchSize)
	if err != nil {
		w.log.Error("claim pending deliveries", "err", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	if err := w.store.MarkDeliveriesProcessing(ctx, ids); err != nil {
		w.log.Error("mark deliveries processing", "err", err)
		return
	}

	for _, row := range rows {
		row := row
		sem := w.semaphore(row.OrgID)
		sem <- struct{}{} // acquire per-org slot
		w.wg.Add(1)
		go func() {
			defer func() { <-sem }()
			defer w.wg.Done()
			w.deliver(ctx, row)
		}()
	}
}

func (w *Worker) deliver(ctx context.Context, row store.ClaimedDelivery) {
	ch, err := w.store.GetNotificationChannelForDelivery(ctx, row.ChannelID)
	if err != nil || ch == nil {
		msg := "channel lookup failed"
		if err != nil {
			msg = fmt.Sprintf("channel lookup failed: %v", err)
		}
		w.log.Error("get channel for delivery", "channel_id", row.ChannelID, "err", err)
		w.exhaust(ctx, row.ID, msg)
		return
	}

	var config struct {
		URL           string            `json:"url"`
		CustomHeaders map[string]string `json:"custom_headers"`
	}
	_ = json.Unmarshal(ch.Config, &config) //nolint:errcheck

	sendErr := Send(ctx, w.client, WebhookConfig{
		URL:           config.URL,
		SigningSecret: ch.SigningSecret,
		CustomHeaders: config.CustomHeaders,
	}, row.Payload)

	if sendErr == nil {
		if err := w.store.CompleteDelivery(ctx, row.ID); err != nil {
			w.log.Error("complete delivery", "id", row.ID, "err", err)
		}
		return
	}

	nextAttempt := int(row.AttemptCount) + 1
	w.log.Warn("delivery failed", "id", row.ID, "err", sendErr, "attempt", nextAttempt)
	if nextAttempt >= w.cfg.MaxAttempts {
		w.exhaust(ctx, row.ID, sendErr.Error())
		return
	}

	backoff := w.backoffSeconds(nextAttempt)
	if err := w.store.RetryDelivery(ctx, row.ID, backoff, sendErr.Error()); err != nil {
		w.log.Error("retry delivery", "id", row.ID, "err", err)
	}
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
	return w.sems[orgID]
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
