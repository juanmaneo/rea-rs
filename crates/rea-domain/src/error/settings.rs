//! Accepted runtime-setting limits that a refusal binds at its producing boundary.
//!
//! The failing owner supplies the limit facts; REA never infers them from
//! error prose. A continuing caller can change the setting on its session; a
//! finished invocation can only choose the launch-environment seed or per-call
//! argument of a new invocation, so the projection re-scopes the same facts.
//!
//! Upstream reference: `upstream:src/domain/analysisSettings.ts` and
//! `upstream:src/domain/analysisSettingDefinitions.ts`.

use serde_json::{Map, Value};

use super::CallerLifetime;

/// Largest delay a Node.js timer accepts; upstream bounds millisecond settings by it.
const MAX_TIMER_DELAY_MS: u64 = 2_147_483_647;

/// A runtime analysis setting that an agent can change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalysisSettingId {
    /// `asar.max_header_bytes`.
    AsarMaxHeaderBytes,
    /// `ghidra.startup_timeout_ms`.
    GhidraStartupTimeoutMs,
    /// `hopper.startup_timeout_ms`.
    HopperStartupTimeoutMs,
    /// `ghidra.decompile_timeout_seconds`; its effective value may be `null`.
    GhidraDecompileTimeoutSeconds,
    /// `jadx.operation_timeout_ms`.
    JadxOperationTimeoutMs,
    /// `regex.matching_deadline_ms`.
    RegexMatchingDeadlineMs,
    /// `regex.worker_heap_request_mib`.
    RegexWorkerHeapRequestMib,
    /// `capture.decoder_old_generation_mib`.
    CaptureDecoderOldGenerationMib,
    /// `javascript.analysis_timeout_ms`.
    JavascriptAnalysisTimeoutMs,
    /// `javascript.max_heap_mb`.
    JavascriptMaxHeapMb,
    /// `wasm.command_timeout_ms`.
    WasmCommandTimeoutMs,
    /// `native.matching_representation_bytes`.
    NativeMatchingRepresentationBytes,
}

/// Unit of a setting's numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingUnit {
    /// `bytes`.
    Bytes,
    /// `ms`.
    Milliseconds,
    /// `seconds`.
    Seconds,
    /// `MiB`.
    Mebibytes,
}

impl SettingUnit {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Milliseconds => "ms",
            Self::Seconds => "seconds",
            Self::Mebibytes => "MiB",
        }
    }
}

/// Where the effective value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingSource {
    /// `default`.
    Default,
    /// `setting`: a runtime override.
    Setting,
    /// `runtime`.
    Runtime,
    /// `request`: an explicit per-call argument.
    Request,
}

impl SettingSource {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Setting => "setting",
            Self::Runtime => "runtime",
            Self::Request => "request",
        }
    }
}

/// When a changed runtime value takes effect for a continuing caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingAppliesAt {
    /// `next_operation`.
    NextOperation,
    /// `next_worker`.
    NextWorker,
    /// `next_startup`.
    NextStartup,
}

impl SettingAppliesAt {
    /// Contract text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NextOperation => "next_operation",
            Self::NextWorker => "next_worker",
            Self::NextStartup => "next_startup",
        }
    }
}

struct SettingDefinition {
    environment: Option<&'static str>,
    minimum: u64,
    maximum: u64,
    unit: SettingUnit,
    applies_at: SettingAppliesAt,
    parameter: Option<&'static str>,
}

const fn timer(
    environment: Option<&'static str>,
    applies_at: SettingAppliesAt,
) -> SettingDefinition {
    SettingDefinition {
        environment,
        minimum: 1,
        maximum: MAX_TIMER_DELAY_MS,
        unit: SettingUnit::Milliseconds,
        applies_at,
        parameter: None,
    }
}

impl AnalysisSettingId {
    /// Every setting, in upstream definition order.
    pub const ALL: [Self; 12] = [
        Self::AsarMaxHeaderBytes,
        Self::GhidraStartupTimeoutMs,
        Self::HopperStartupTimeoutMs,
        Self::GhidraDecompileTimeoutSeconds,
        Self::JadxOperationTimeoutMs,
        Self::RegexMatchingDeadlineMs,
        Self::RegexWorkerHeapRequestMib,
        Self::CaptureDecoderOldGenerationMib,
        Self::JavascriptAnalysisTimeoutMs,
        Self::JavascriptMaxHeapMb,
        Self::WasmCommandTimeoutMs,
        Self::NativeMatchingRepresentationBytes,
    ];

    /// Stable setting identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsarMaxHeaderBytes => "asar.max_header_bytes",
            Self::GhidraStartupTimeoutMs => "ghidra.startup_timeout_ms",
            Self::HopperStartupTimeoutMs => "hopper.startup_timeout_ms",
            Self::GhidraDecompileTimeoutSeconds => "ghidra.decompile_timeout_seconds",
            Self::JadxOperationTimeoutMs => "jadx.operation_timeout_ms",
            Self::RegexMatchingDeadlineMs => "regex.matching_deadline_ms",
            Self::RegexWorkerHeapRequestMib => "regex.worker_heap_request_mib",
            Self::CaptureDecoderOldGenerationMib => "capture.decoder_old_generation_mib",
            Self::JavascriptAnalysisTimeoutMs => "javascript.analysis_timeout_ms",
            Self::JavascriptMaxHeapMb => "javascript.max_heap_mb",
            Self::WasmCommandTimeoutMs => "wasm.command_timeout_ms",
            Self::NativeMatchingRepresentationBytes => "native.matching_representation_bytes",
        }
    }

    /// Launch-environment seed a new invocation reads, when one exists.
    pub fn environment(self) -> Option<&'static str> {
        self.definition().environment
    }

    fn definition(self) -> SettingDefinition {
        use SettingAppliesAt::{NextOperation, NextStartup, NextWorker};
        match self {
            Self::AsarMaxHeaderBytes => SettingDefinition {
                environment: Some("REA_ASAR_MAX_HEADER_BYTES"),
                minimum: 1,
                maximum: 256 * 1024 * 1024,
                unit: SettingUnit::Bytes,
                applies_at: NextOperation,
                parameter: None,
            },
            Self::GhidraStartupTimeoutMs => {
                timer(Some("REA_GHIDRA_STARTUP_TIMEOUT_MS"), NextStartup)
            }
            Self::HopperStartupTimeoutMs => {
                timer(Some("REA_HOPPER_STARTUP_TIMEOUT_MS"), NextStartup)
            }
            Self::GhidraDecompileTimeoutSeconds => SettingDefinition {
                environment: Some("REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS"),
                minimum: 1,
                maximum: MAX_TIMER_DELAY_MS / 1000,
                unit: SettingUnit::Seconds,
                applies_at: NextOperation,
                parameter: None,
            },
            Self::JadxOperationTimeoutMs => {
                timer(Some("REA_JADX_OPERATION_TIMEOUT_MS"), NextOperation)
            }
            Self::RegexMatchingDeadlineMs => {
                timer(Some("REA_REGEX_MATCHING_DEADLINE_MS"), NextOperation)
            }
            Self::RegexWorkerHeapRequestMib => SettingDefinition {
                environment: Some("REA_REGEX_WORKER_HEAP_REQUEST_MIB"),
                minimum: 7,
                maximum: 16_384,
                unit: SettingUnit::Mebibytes,
                applies_at: NextWorker,
                parameter: None,
            },
            Self::CaptureDecoderOldGenerationMib => SettingDefinition {
                environment: Some("REA_CAPTURE_DECODER_OLD_GENERATION_MIB"),
                minimum: 8,
                maximum: 16_384,
                unit: SettingUnit::Mebibytes,
                applies_at: NextWorker,
                parameter: None,
            },
            Self::JavascriptAnalysisTimeoutMs => SettingDefinition {
                parameter: Some("analysis_timeout_ms"),
                ..timer(None, NextOperation)
            },
            Self::JavascriptMaxHeapMb => SettingDefinition {
                environment: None,
                minimum: 128,
                maximum: 16_384,
                unit: SettingUnit::Mebibytes,
                applies_at: NextWorker,
                parameter: Some("max_heap_mb"),
            },
            Self::WasmCommandTimeoutMs => SettingDefinition {
                parameter: Some("command_timeout_ms"),
                ..timer(None, NextOperation)
            },
            Self::NativeMatchingRepresentationBytes => SettingDefinition {
                environment: Some("REA_NATIVE_MATCHING_REPRESENTATION_BYTES"),
                minimum: 1,
                maximum: 1024 * 1024 * 1024,
                unit: SettingUnit::Bytes,
                applies_at: NextOperation,
                parameter: None,
            },
        }
    }
}

/// One owner's accepted budget, as `analysisSettingLimit` projects it.
///
/// `agent_editable: true`, `scope: "rea-runtime"`, and
/// `rea_restart_required: false` are constant in the contract and therefore
/// not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisSettingLimit {
    /// The enforced setting.
    pub setting: AnalysisSettingId,
    /// Effective value; `None` projects as `null`.
    pub effective_value: Option<u64>,
    /// Where the effective value came from, when the owner knows.
    pub source: Option<SettingSource>,
    /// Value unit.
    pub unit: SettingUnit,
    /// Smallest accepted value.
    pub minimum: u64,
    /// Largest accepted value.
    pub maximum: u64,
    /// When a runtime change applies for a continuing caller.
    pub applies_at: SettingAppliesAt,
    /// Per-call argument that overrides the setting, when one exists.
    pub parameter: Option<&'static str>,
    /// Value the refused request needed, when the owner measured it.
    pub required_value: Option<u64>,
}

impl AnalysisSettingLimit {
    /// Project the setting's definition with the owner's effective value and source.
    pub fn new(
        setting: AnalysisSettingId,
        effective_value: Option<u64>,
        source: Option<SettingSource>,
    ) -> Self {
        let definition = setting.definition();
        Self {
            setting,
            effective_value,
            source,
            unit: definition.unit,
            minimum: definition.minimum,
            maximum: definition.maximum,
            applies_at: definition.applies_at,
            parameter: definition.parameter,
            required_value: None,
        }
    }

    /// Record the value the refused request needed.
    #[must_use]
    pub fn with_required_value(mut self, required_value: u64) -> Self {
        self.required_value = Some(required_value);
        self
    }

    /// The limit as a caller with `lifetime` can act on it.
    ///
    /// An invocation caller receives `applies_at: "next_invocation"`,
    /// `scope: "rea-invocation"`, and the launch environment seed, appended
    /// after the enforced facts as upstream's `invocationSettingLimit` does.
    pub fn to_value(&self, lifetime: CallerLifetime) -> Value {
        let mut limit = Map::new();
        limit.insert("setting".into(), self.setting.as_str().into());
        limit.insert(
            "effective_value".into(),
            self.effective_value.map_or(Value::Null, Value::from),
        );
        if let Some(source) = self.source {
            limit.insert("source".into(), source.as_str().into());
        }
        limit.insert("unit".into(), self.unit.as_str().into());
        limit.insert("minimum".into(), self.minimum.into());
        limit.insert("maximum".into(), self.maximum.into());
        if lifetime == CallerLifetime::Continuing {
            limit.insert("applies_at".into(), self.applies_at.as_str().into());
        }
        limit.insert("agent_editable".into(), true.into());
        if lifetime == CallerLifetime::Continuing {
            limit.insert("scope".into(), "rea-runtime".into());
        }
        limit.insert("rea_restart_required".into(), false.into());
        if let Some(parameter) = self.parameter {
            limit.insert("parameter".into(), parameter.into());
        }
        if let Some(required) = self.required_value {
            limit.insert("required_value".into(), required.into());
        }
        if lifetime == CallerLifetime::Invocation {
            limit.insert("applies_at".into(), "next_invocation".into());
            limit.insert("scope".into(), "rea-invocation".into());
            if let Some(environment) = self.setting.environment() {
                limit.insert("environment".into(), environment.into());
            }
        }
        Value::Object(limit)
    }
}
