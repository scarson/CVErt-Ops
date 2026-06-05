//! Rust fixture for the performance-audit evals: an axum + tokio + sqlx service
//! exercising the core Rust lanes + the web, async-tokio, and database modules +
//! Runtime & build notes. Illustrative (not built). See expected-findings.md
//! (do NOT read it as the agent under test).

use std::sync::{Arc, Mutex};

// PLANTED #1 (module: web): AppState derives Clone on a big owned struct, so every
// handler dispatch DEEP-COPIES the whole config + cache. It should hold its heavy
// fields behind `Arc` (clone = refcount bump), or the whole state be `Arc<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,             // large, owned
    pub catalog: Vec<Product>,      // thousands of entries, cloned per request
    pub pool: sqlx::PgPool,         // (PgPool clone is cheap — this one is fine)
}

pub async fn order_handler(state: AppState, ids: Vec<i64>) -> Vec<Row> {
    // PLANTED #2 (module: database): N+1 — one query per id in a loop instead of one
    // `WHERE id = ANY($1)`. Each await is a round-trip.
    let mut rows = Vec::new();
    for id in &ids {
        let row = sqlx::query_as::<_, Row>("SELECT id, name FROM items WHERE id = $1")
            .bind(id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        rows.push(row);
    }
    rows
}

// PLANTED #3 (module: async-tokio): a std::sync::Mutex guard held ACROSS an `.await`
// point — stalls the executor thread for the whole suspension, and risks deadlock.
// Scope/drop the guard before awaiting.
pub async fn record_metric(counter: Arc<Mutex<u64>>, db: &sqlx::PgPool) {
    let mut guard = counter.lock().unwrap();
    *guard += 1;
    sqlx::query("INSERT INTO metrics(n) VALUES ($1)")
        .bind(*guard as i64)
        .execute(db)        // .await while holding the std Mutex guard
        .await
        .unwrap();
}

// PLANTED #4 (core concurrency): two INDEPENDENT awaits run sequentially; latency is
// the sum. `tokio::join!(a, b)` runs them concurrently. Independence holds (distinct
// endpoints, no shared mutable state) — state the guard.
pub async fn dashboard(state: &AppState) -> (Summary, Summary) {
    let revenue = fetch_revenue(&state.pool).await;
    let refunds = fetch_refunds(&state.pool).await;
    (revenue, refunds)
}

pub struct Config;
#[derive(Clone)]
pub struct Product;
pub struct Row;
pub struct Summary;
async fn fetch_revenue(_p: &sqlx::PgPool) -> Summary { Summary }
async fn fetch_refunds(_p: &sqlx::PgPool) -> Summary { Summary }
