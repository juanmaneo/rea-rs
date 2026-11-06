//! Caller cancellation shared across blocking and asynchronous work.
//!
//! Upstream reference: the `AbortSignal` threaded through
//! `ExecutionOptions.signal` in `upstream:src/application/AnalysisProvider.ts`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A cloneable, one-way cancellation flag.
///
/// Every clone observes the same state. Once cancelled it stays cancelled.
#[derive(Debug, Clone, Default)]
pub struct CancellationSignal {
    cancelled: Arc<AtomicBool>,
}

impl CancellationSignal {
    /// A signal that has not been cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// A signal driven by an externally owned flag, such as one an OS signal
    /// handler sets. The owner must only ever set the flag, never clear it.
    pub fn from_flag(flag: Arc<AtomicBool>) -> Self {
        Self { cancelled: flag }
    }

    /// Request cancellation for every clone of this signal.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}
