//! Recovery for deterministic producer allowances and resource refusals.
//!
//! A fixed allowance is a format, decoder, or capture bound that host memory,
//! worker limits, waiting, or another output channel do not raise. A refusal
//! carries either such an allowance or a producer remediation sentence, never
//! both; retryability belongs to the same recovery.
//!
//! Upstream reference: `upstream:src/domain/fixedAllowanceRemediation.ts` and
//! `ResourceConstraintRecovery` in `upstream:src/domain/analysisErrorCore.ts`.

/// Recovery family of a fixed allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixedAllowanceKind {
    /// Parser working-set allowance.
    Parser,
    /// Fixed count.
    Count,
    /// Fixed byte allowance.
    Bytes,
    /// Fixed report allowance.
    Report,
    /// Producer input allowance.
    Input,
    /// Fixed capture allowance.
    Capture,
    /// Capture allowance over live output that may change between requests.
    Live,
    /// Fixed work allowance.
    Work,
}

impl FixedAllowanceKind {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Count => "count",
            Self::Bytes => "bytes",
            Self::Report => "report",
            Self::Input => "input",
            Self::Capture => "capture",
            Self::Live => "live",
            Self::Work => "work",
        }
    }
}

/// A named deterministic allowance and the recovery family it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedAllowance {
    /// Display name, such as "The tshark JSON decoding allowance".
    pub name: String,
    /// Recovery family.
    pub kind: FixedAllowanceKind,
}

impl FixedAllowance {
    /// Name an allowance.
    pub fn new(name: impl Into<String>, kind: FixedAllowanceKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }

    /// A fixed producer input allowance in bytes, which has no runtime override.
    pub fn producer_input(bytes: u64, allowance: &str) -> Self {
        Self::new(
            format!("{allowance} of {bytes} bytes (this release has no runtime override)"),
            FixedAllowanceKind::Input,
        )
    }

    /// The recovery sentence derived from this allowance.
    pub fn remediation(&self) -> String {
        fixed_allowance_remediation(&self.name, self.kind)
    }
}

const UNCHANGED_REQUEST: &str = "Repeating the unchanged request fails the same way.";

/// Name the fixed allowance and the recovery that cannot admit the same request.
pub fn fixed_allowance_remediation(allowance: &str, kind: FixedAllowanceKind) -> String {
    match kind {
        FixedAllowanceKind::Parser => format!(
            "{allowance} is a fixed allowance. Worker memory limits, inherited limits, and additional host memory do not raise it. Select another complete input within the allowance when that preserves the needed observation. {UNCHANGED_REQUEST}"
        ),
        FixedAllowanceKind::Count => format!(
            "{allowance} is a fixed count. Waiting for an active analysis to finish does not raise it. {UNCHANGED_REQUEST}"
        ),
        FixedAllowanceKind::Bytes => format!(
            "{allowance} is a fixed byte allowance. Waiting for an active analysis to finish does not raise it. {UNCHANGED_REQUEST}"
        ),
        FixedAllowanceKind::Report => format!(
            "{allowance} is a fixed report allowance. This refusal does not leave a completed report or Evidence record to retrieve, and complete CLI JSON does not raise it. {UNCHANGED_REQUEST}"
        ),
        FixedAllowanceKind::Input => format!(
            "Select a suitable complete artifact within {allowance}. Increasing an evidence-reply file-size allowance does not admit this input. Do not truncate required bytes. {UNCHANGED_REQUEST}"
        ),
        FixedAllowanceKind::Capture => format!(
            "{allowance} is a fixed capture allowance. Worker memory limits, inherited limits, and additional host memory do not raise it. {UNCHANGED_REQUEST}"
        ),
        FixedAllowanceKind::Live => format!(
            "{allowance} is a fixed capture allowance. Worker memory limits, inherited limits, and additional host memory do not raise it. Capturing the same output exceeds the allowance again; live output may change between requests."
        ),
        FixedAllowanceKind::Work => format!(
            "{allowance} is a fixed work allowance. Worker CPU limits and additional CPU time do not raise it. Select another complete artifact within the allowance. {UNCHANGED_REQUEST}"
        ),
    }
}

/// The one recovery a resource refusal carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceConstraintRecovery {
    /// Producer-specific remediation, or the resource kind's default when absent.
    Remediation {
        /// Replaces the resource kind's default remediation.
        action: Option<String>,
        /// Overrides the default (only `capacity` refusals are retryable).
        retryable: Option<bool>,
    },
    /// A fixed allowance whose remediation is derived from it.
    FixedAllowance {
        /// The allowance that refused the request.
        allowance: FixedAllowance,
        /// Overrides the default (only `capacity` refusals are retryable).
        retryable: Option<bool>,
    },
}

impl Default for ResourceConstraintRecovery {
    fn default() -> Self {
        Self::Remediation {
            action: None,
            retryable: None,
        }
    }
}

impl ResourceConstraintRecovery {
    /// A non-retryable fixed allowance, as upstream's `fixedAllowanceOptions`.
    pub fn fixed(allowance: FixedAllowance) -> Self {
        Self::FixedAllowance {
            allowance,
            retryable: Some(false),
        }
    }

    /// A producer remediation sentence; retryability follows the resource kind.
    pub fn remediation(action: impl Into<String>) -> Self {
        Self::Remediation {
            action: Some(action.into()),
            retryable: None,
        }
    }

    /// A producer remediation sentence for a deterministic, non-retryable refusal.
    pub fn non_retryable(action: impl Into<String>) -> Self {
        Self::Remediation {
            action: Some(action.into()),
            retryable: Some(false),
        }
    }

    /// Producer remediation, absent when the recovery names a fixed allowance.
    pub fn remediation_action(&self) -> Option<&str> {
        match self {
            Self::Remediation { action, .. } => action.as_deref(),
            Self::FixedAllowance { .. } => None,
        }
    }

    /// The fixed allowance that refused the request, if any.
    pub fn fixed_allowance(&self) -> Option<&FixedAllowance> {
        match self {
            Self::Remediation { .. } => None,
            Self::FixedAllowance { allowance, .. } => Some(allowance),
        }
    }

    /// Explicit retryability, when the producer decided it.
    pub fn retryable(&self) -> Option<bool> {
        match self {
            Self::Remediation { retryable, .. } | Self::FixedAllowance { retryable, .. } => {
                *retryable
            }
        }
    }
}
