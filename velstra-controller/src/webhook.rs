//! Webhook delivery for fabric change events (roadmap D1).
//!
//! The [`/v1/events`](crate::rest) SSE stream serves consumers that can hold a
//! connection open. A webhook serves the ones that cannot: the controller POSTs
//! each audit record to a configured URL as JSON.
//!
//! Two properties matter more than delivery guarantees here, and both shape the
//! design:
//!
//! * **A webhook endpoint must never slow the fabric down.** Delivery runs in its
//!   own task off the same bounded broadcast the SSE stream uses, so a hung
//!   endpoint blocks nothing — it falls behind and is told how far.
//! * **One bad endpoint must not silence the others.** Each URL gets its own task
//!   and its own subscription, so they lag, retry and fail independently.
//!
//! Delivery is therefore **best-effort with bounded retries**, not exactly-once.
//! A consumer that needs completeness reconciles against `GET /v1/audit`, which
//! is why every record carries a monotonic `seq`.

use std::{sync::Arc, time::Duration};

use log::{debug, info, warn};
use tokio::sync::broadcast;

use crate::rest::{Audit, AuditEntry};

/// How long a single POST may take before it is abandoned.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// How many times one record is retried before it is dropped. Bounded on
/// purpose: retrying forever would turn a dead endpoint into an ever-growing
/// backlog, and the record is still in `GET /v1/audit` either way.
const MAX_ATTEMPTS: u32 = 3;

/// Base delay for the exponential backoff between attempts.
const RETRY_BASE: Duration = Duration::from_millis(200);

/// Spawn one delivery task per URL. Returns immediately; each task lives for the
/// life of the process.
pub fn spawn(audit: &Arc<Audit>, urls: &[String]) {
    if urls.is_empty() {
        return;
    }
    let client = match reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            // Without a client there is nothing to deliver with; say so loudly
            // rather than leaving an operator waiting for events that never come.
            warn!("webhook delivery disabled: building the HTTP client failed: {e}");
            return;
        }
    };
    for url in urls {
        info!("webhook delivery to {url}");
        tokio::spawn(deliver_loop(client.clone(), url.clone(), audit.subscribe()));
    }
}

/// Consume the record stream for one endpoint until the process ends.
async fn deliver_loop(
    client: reqwest::Client,
    url: String,
    mut rx: broadcast::Receiver<AuditEntry>,
) {
    loop {
        match rx.recv().await {
            Ok(entry) => post_with_retries(&client, &url, &entry).await,
            // This endpoint fell behind and the channel dropped records for it.
            // Its own problem, not the fabric's — name the gap and carry on; the
            // missed records remain readable at GET /v1/audit.
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("webhook {url} lagged, {n} record(s) dropped; see GET /v1/audit");
            }
            // The audit log is gone, i.e. the process is shutting down.
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// POST one record, retrying a bounded number of times on a transport error or a
/// non-2xx response.
async fn post_with_retries(client: &reqwest::Client, url: &str, entry: &AuditEntry) {
    for attempt in 1..=MAX_ATTEMPTS {
        match client.post(url).json(entry).send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!("webhook {url} delivered seq {}", entry.seq);
                return;
            }
            Ok(resp) => {
                warn!(
                    "webhook {url} seq {} attempt {attempt}/{MAX_ATTEMPTS}: HTTP {}",
                    entry.seq,
                    resp.status()
                );
            }
            Err(e) => {
                warn!(
                    "webhook {url} seq {} attempt {attempt}/{MAX_ATTEMPTS}: {e}",
                    entry.seq
                );
            }
        }
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(backoff(attempt)).await;
        }
    }
    warn!(
        "webhook {url} gave up on seq {} after {MAX_ATTEMPTS} attempts",
        entry.seq
    );
}

/// Exponential backoff: 200ms, 400ms, 800ms, … Kept small — a webhook consumer
/// wants timeliness, and a genuinely dead endpoint is better abandoned than
/// slowly retried.
fn backoff(attempt: u32) -> Duration {
    RETRY_BASE * 2u32.pow(attempt - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_stays_bounded() {
        assert_eq!(backoff(1), Duration::from_millis(200));
        assert_eq!(backoff(2), Duration::from_millis(400));
        // The last delay before giving up: total added latency stays under a
        // second, so a dead endpoint cannot hold a delivery task for long.
        assert_eq!(backoff(MAX_ATTEMPTS - 1), Duration::from_millis(400));
    }
}
