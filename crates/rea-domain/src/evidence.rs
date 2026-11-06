//! The provider-neutral record for one successful public observation.
//!
//! An Evidence identifier commits to the record's semantic content: the
//! subject's digest/format/architecture, provider, profile, operation,
//! parameters, results, confidence, authority, environment, limitations,
//! coverage, locations, and links. Local display metadata (`subject.name`,
//! `subject.local_path`, `caller_input_path`) is excluded, so rebinding a
//! selected path never changes identity.
//!
//! Upstream reference: `upstream:src/domain/evidence.ts` and
//! `upstream:src/domain/evidenceSubject.ts`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::digest::{EvidenceFamily, PrefixedDigest, Sha256Digest};
use crate::json::canonical_digest;

/// Semantic Evidence identifier, `ev_<sha256>`.
pub type EvidenceId = PrefixedDigest<EvidenceFamily>;

/// Predicate shared by ordinary provider analysis observations.
pub const ANALYSIS_EVIDENCE_PREDICATE: &str = "rea.analysis";

/// Limitation recorded when an observation has no artifact identity.
pub const SUBJECT_UNAVAILABLE_LIMITATION: &str =
    "Artifact identity is unavailable for this observation.";

/// Provider identity shared by evidence-bearing persistence formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvider {
    /// Stable provider identifier, for example `rea-elf-notes`.
    pub id: String,
    /// Human-readable provider name.
    pub name: String,
    /// Provider version, when known.
    pub version: Option<String>,
}

/// Binary architecture families.
///
/// Upstream reference: `BINARY_ARCHITECTURES` in `upstream:src/domain/binaryTargetTypes.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinaryArchitecture {
    /// 32-bit x86.
    #[serde(rename = "x86")]
    X86,
    /// x86-64.
    #[serde(rename = "x86_64")]
    X86_64,
    /// 32-bit Arm.
    #[serde(rename = "arm")]
    Arm,
    /// AArch64.
    #[serde(rename = "arm64")]
    Arm64,
    /// AArch64 with 32-bit pointers.
    #[serde(rename = "arm64_32")]
    Arm64_32,
    /// MIPS; ISA, ABI and byte order remain separate facts.
    #[serde(rename = "mips")]
    Mips,
    /// MOS 6502; raw-binary selection only.
    #[serde(rename = "6502")]
    Mos6502,
    /// RISC-V; XLEN, byte order and flags remain separate facts.
    #[serde(rename = "riscv")]
    RiscV,
    /// PowerPC.
    #[serde(rename = "powerpc")]
    PowerPc,
    /// Motorola 68k; raw-binary selection only.
    #[serde(rename = "m68k")]
    M68k,
    /// Qualcomm Hexagon.
    #[serde(rename = "hexagon")]
    Hexagon,
}

impl BinaryArchitecture {
    /// Families admitted only by explicit raw-binary selection.
    pub const fn is_raw_only(self) -> bool {
        matches!(self, Self::Mos6502 | Self::M68k)
    }

    /// The architecture an ELF `e_machine` value declares, when REA models it.
    ///
    /// Upstream reference: `elfArchitecture` in `upstream:src/domain/elfFixedHeader.ts`.
    pub const fn from_elf_machine(machine: u16) -> Option<Self> {
        match machine {
            3 => Some(Self::X86),
            62 => Some(Self::X86_64),
            8 => Some(Self::Mips),
            20 => Some(Self::PowerPc),
            40 => Some(Self::Arm),
            164 => Some(Self::Hexagon),
            183 => Some(Self::Arm64),
            243 => Some(Self::RiscV),
            _ => None,
        }
    }
}

/// Artifact formats an Evidence subject may declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum SubjectFormat {
    Hopper,
    AnalysisDatabase,
    MachO,
    Elf,
    Pe,
    DosMz,
    DosCom,
    RawBinary,
    GamecubeDol,
    Zip,
    Ipa,
    Apk,
    Msix,
    Appx,
    Hap,
    Hsp,
    AppPack,
    Asar,
    Ines,
    GodotPck,
    Unityfs,
    Wxapkg,
    Uimage,
    Dmg,
    Pkg,
    Plist,
    Javascript,
    SourceMap,
    Directory,
    File,
    Unknown,
    MachOUniversal,
    JavascriptBundle,
    Entitlements,
    Pyinstaller,
    NodeSea,
    DotnetBundle,
    BunStandalone,
    IntelHex,
    Srec,
    EspImage,
    Uf2,
    Dfuse,
    EspFlashImage,
    Fit,
}

impl SubjectFormat {
    /// Whether this format may declare `architecture`.
    pub fn admits(self, architecture: Option<BinaryArchitecture>) -> bool {
        match (self, architecture) {
            (Self::RawBinary, _) => true,
            (Self::GamecubeDol, architecture) => architecture == Some(BinaryArchitecture::PowerPc),
            (_, None) => true,
            (_, Some(architecture)) => !architecture.is_raw_only(),
        }
    }
}

/// SHA-256 wrapper object used by Evidence subjects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectDigest {
    /// Artifact content digest.
    pub sha256: Sha256Digest,
}

/// The immutable artifact an Evidence record observes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSubject {
    /// Display name, the final path component.
    pub name: String,
    /// Content identity.
    pub digest: SubjectDigest,
    /// Caller-selected local path; display metadata only.
    pub local_path: String,
    /// Declared format.
    pub format: SubjectFormat,
    /// Declared architecture, when the format establishes one.
    pub architecture: Option<BinaryArchitecture>,
}

/// Candidate local artifact identity for a new Evidence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSubjectTarget {
    /// Selected absolute path, as caller-visible text.
    pub path: String,
    /// Content digest.
    pub sha256: Sha256Digest,
    /// Declared format.
    pub format: SubjectFormat,
    /// Declared architecture.
    pub architecture: Option<BinaryArchitecture>,
}

/// Source location attached to an observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EvidenceLocation {
    /// One address in the provider's address space.
    Address {
        /// Address text as the provider reports it.
        address: String,
    },
    /// A half-open address range.
    AddressRange {
        /// Start address text.
        start: String,
        /// End address text.
        end: String,
    },
    /// A path inside or naming the artifact.
    ArtifactPath {
        /// Path text.
        path: String,
    },
    /// One byte offset in the original file.
    FileOffset {
        /// Byte offset.
        offset: u64,
    },
    /// A half-open byte range in the original file.
    FileOffsetRange {
        /// Start offset.
        start: u64,
        /// End offset.
        end: u64,
    },
}

/// How directly a result was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Read directly from the source.
    Observed,
    /// Computed deterministically from observations.
    Derived,
    /// Inferred; may be wrong.
    Inferred,
}

/// Source authority vocabulary owned by Evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceAuthority {
    /// The shipped artifact itself.
    ShippedArtifact,
    /// A controlled replay.
    ControlledReplay,
    /// Historical reference material.
    HistoricalReference,
    /// An external service.
    ExternalService,
    /// Analyst inference.
    AnalystInference,
}

/// Isolation of an execution environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum EnvironmentIsolation {
    None,
    Process,
    Container,
    VirtualMachine,
}

/// Environment in which a dynamic observation was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnvironment {
    /// Environment identifier.
    pub id: String,
    /// Platform name.
    pub platform: String,
    /// Architecture name.
    pub architecture: String,
    /// Isolation level.
    pub isolation: EnvironmentIsolation,
}

/// One authenticated Evidence record.
///
/// Field order matches upstream's parsed record so serialized output keeps the
/// same member order. `caller_input_path` is appended last, as upstream's
/// caller-path rebinding does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Semantic identifier.
    pub evidence_id: EvidenceId,
    /// Observed artifact, or null when identity is unavailable.
    pub subject: Option<EvidenceSubject>,
    /// Observing provider.
    pub provider: EvidenceProvider,
    /// Analysis profile commitment. Typed port pending (`upstream:src/domain/analysisProfile.ts`).
    pub analysis_profile: Option<Value>,
    /// Predicate type, usually [`ANALYSIS_EVIDENCE_PREDICATE`].
    pub predicate_type: String,
    /// Public operation name.
    pub operation: String,
    /// Accepted operation parameters.
    pub parameters: Map<String, Value>,
    /// Raw provider result, when retained.
    pub raw_result: Value,
    /// Normalized operation result.
    pub normalized_result: Value,
    /// Confidence of the result.
    pub confidence: Confidence,
    /// Source authority.
    pub authority: EvidenceAuthority,
    /// Execution environment for dynamic observations.
    pub environment: Option<ExecutionEnvironment>,
    /// Known limitations of this observation.
    pub limitations: Vec<String>,
    /// Caller/callee relationship coverage. Typed port pending
    /// (`upstream:src/domain/relationshipCoverage.ts`).
    pub relationship_coverage: Option<Value>,
    /// Source locations.
    pub locations: Vec<EvidenceLocation>,
    /// Linked Evidence.
    pub evidence_links: Vec<EvidenceId>,
    /// Verbatim direct-request path; not part of semantic identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_input_path: Option<String>,
}

/// Producer facts admitted into a new Evidence record.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceObservation {
    /// Public operation name.
    pub operation: String,
    /// Accepted parameters.
    pub parameters: Map<String, Value>,
    /// Normalized result.
    pub result: Value,
    /// Raw result, when retained.
    pub raw_result: Option<Value>,
    /// Predicate type; defaults to [`ANALYSIS_EVIDENCE_PREDICATE`].
    pub predicate_type: Option<String>,
    /// Confidence; defaults to observed.
    pub confidence: Confidence,
    /// Authority; defaults to the shipped artifact.
    pub authority: EvidenceAuthority,
    /// Execution environment.
    pub environment: Option<ExecutionEnvironment>,
    /// Limitations.
    pub limitations: Vec<String>,
    /// Reason the subject is unavailable when no target is supplied.
    pub subject_unavailable_reason: Option<String>,
    /// Locations.
    pub locations: Vec<EvidenceLocation>,
    /// Linked Evidence.
    pub evidence_links: Vec<EvidenceId>,
}

impl EvidenceObservation {
    /// An observed shipped-artifact result with no optional facts.
    pub fn new(
        operation: impl Into<String>,
        parameters: Map<String, Value>,
        result: Value,
    ) -> Self {
        Self {
            operation: operation.into(),
            parameters,
            result,
            raw_result: None,
            predicate_type: None,
            confidence: Confidence::Observed,
            authority: EvidenceAuthority::ShippedArtifact,
            environment: None,
            limitations: Vec::new(),
            subject_unavailable_reason: None,
            locations: Vec::new(),
            evidence_links: Vec::new(),
        }
    }
}

/// An Evidence record that violates its envelope contract.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    /// A required text field is empty.
    #[error("Evidence {0} must not be empty")]
    EmptyField(&'static str),
    /// A local path contains NUL.
    #[error("Local filesystem paths cannot contain NUL")]
    NulInPath,
    /// The subject format cannot declare the architecture.
    #[error("Evidence subject format does not admit its architecture")]
    SubjectArchitecture,
    /// The identifier does not commit to the record's content.
    #[error("Evidence semantic identifier does not match its record")]
    IdentityMismatch,
}

impl Evidence {
    /// Admit producer facts into a deterministic Evidence record.
    pub fn create(
        target: Option<&EvidenceSubjectTarget>,
        provider: &EvidenceProvider,
        observation: EvidenceObservation,
    ) -> Result<Self, EvidenceError> {
        if provider.id.is_empty() {
            return Err(EvidenceError::EmptyField("provider.id"));
        }
        if provider.name.is_empty() {
            return Err(EvidenceError::EmptyField("provider.name"));
        }
        if observation.operation.is_empty() {
            return Err(EvidenceError::EmptyField("operation"));
        }
        let subject = target.map(subject_for).transpose()?;
        let mut limitations = Vec::with_capacity(observation.limitations.len() + 1);
        if subject.is_none() {
            limitations.push(
                observation
                    .subject_unavailable_reason
                    .unwrap_or_else(|| SUBJECT_UNAVAILABLE_LIMITATION.to_owned()),
            );
        }
        limitations.extend(observation.limitations);
        let predicate_type = observation
            .predicate_type
            .unwrap_or_else(|| ANALYSIS_EVIDENCE_PREDICATE.to_owned());
        if predicate_type.is_empty() {
            return Err(EvidenceError::EmptyField("predicate_type"));
        }
        let mut evidence = Self {
            evidence_id: EvidenceId::new(Sha256Digest::from_bytes([0; 32])),
            subject,
            provider: provider.clone(),
            analysis_profile: None,
            predicate_type,
            operation: observation.operation,
            parameters: observation.parameters,
            raw_result: observation.raw_result.unwrap_or(Value::Null),
            normalized_result: observation.result,
            confidence: observation.confidence,
            authority: observation.authority,
            environment: observation.environment,
            limitations,
            relationship_coverage: None,
            locations: observation.locations,
            evidence_links: observation.evidence_links,
            caller_input_path: None,
        };
        evidence.evidence_id = evidence.computed_id();
        Ok(evidence)
    }

    /// Content committed by the identifier, excluding local display metadata.
    pub fn semantic_content(&self) -> Value {
        let subject = self.subject.as_ref().map(|subject| {
            json!({
                "digest": subject.digest,
                "format": subject.format,
                "architecture": subject.architecture,
            })
        });
        json!({
            "subject": subject,
            "provider": self.provider,
            "analysis_profile": self.analysis_profile,
            "predicate_type": self.predicate_type,
            "operation": self.operation,
            "parameters": self.parameters,
            "raw_result": self.raw_result,
            "normalized_result": self.normalized_result,
            "confidence": self.confidence,
            "authority": self.authority,
            "environment": self.environment,
            "limitations": self.limitations,
            "relationship_coverage": self.relationship_coverage,
            "locations": self.locations,
            "evidence_links": self.evidence_links,
        })
    }

    /// The identifier this record's semantic content commits to.
    pub fn computed_id(&self) -> EvidenceId {
        EvidenceId::new(canonical_digest(&self.semantic_content()))
    }

    /// Reject a record whose identifier does not match its content.
    pub fn verify(&self) -> Result<(), EvidenceError> {
        if let Some(subject) = &self.subject
            && !subject.format.admits(subject.architecture)
        {
            return Err(EvidenceError::SubjectArchitecture);
        }
        if self.computed_id() == self.evidence_id {
            Ok(())
        } else {
            Err(EvidenceError::IdentityMismatch)
        }
    }

    /// Bind the exact selected request path without changing semantic identity.
    pub fn with_caller_input_path(
        mut self,
        path: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        let path = path.into();
        if path.contains('\0') {
            return Err(EvidenceError::NulInPath);
        }
        self.caller_input_path = Some(path);
        Ok(self)
    }
}

fn subject_for(target: &EvidenceSubjectTarget) -> Result<EvidenceSubject, EvidenceError> {
    if target.path.contains('\0') {
        return Err(EvidenceError::NulInPath);
    }
    if !target.format.admits(target.architecture) {
        return Err(EvidenceError::SubjectArchitecture);
    }
    let name = Path::new(&target.path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("artifact")
        .to_owned();
    Ok(EvidenceSubject {
        name,
        digest: SubjectDigest {
            sha256: target.sha256,
        },
        local_path: target.path.clone(),
        format: target.format,
        architecture: target.architecture,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> EvidenceProvider {
        EvidenceProvider {
            id: "rea-test".to_owned(),
            name: "REA test".to_owned(),
            version: None,
        }
    }

    fn target(path: &str) -> EvidenceSubjectTarget {
        EvidenceSubjectTarget {
            path: path.to_owned(),
            sha256: Sha256Digest::of(b"artifact"),
            format: SubjectFormat::Elf,
            architecture: Some(BinaryArchitecture::X86_64),
        }
    }

    fn observation() -> EvidenceObservation {
        let mut parameters = Map::new();
        parameters.insert("path".to_owned(), json!("/a/program"));
        EvidenceObservation::new("inspect_fixture", parameters, json!({"answer": 42}))
    }

    #[test]
    fn identity_excludes_display_paths() {
        let first =
            Evidence::create(Some(&target("/a/program")), &provider(), observation()).unwrap();
        let second =
            Evidence::create(Some(&target("/b/renamed")), &provider(), observation()).unwrap();
        assert_eq!(first.evidence_id, second.evidence_id);
        assert_eq!(second.subject.as_ref().unwrap().name, "renamed");
        let bound = first.clone().with_caller_input_path("program").unwrap();
        assert_eq!(bound.evidence_id, first.evidence_id);
        bound.verify().unwrap();
    }

    #[test]
    fn tampered_content_fails_verification() {
        let mut evidence =
            Evidence::create(Some(&target("/a/program")), &provider(), observation()).unwrap();
        evidence.normalized_result = json!({"answer": 43});
        assert_eq!(evidence.verify(), Err(EvidenceError::IdentityMismatch));
    }

    #[test]
    fn missing_subject_records_a_limitation() {
        let evidence = Evidence::create(None, &provider(), observation()).unwrap();
        assert_eq!(evidence.limitations, [SUBJECT_UNAVAILABLE_LIMITATION]);
    }

    #[test]
    fn serialized_member_order_matches_upstream() {
        let evidence = Evidence::create(Some(&target("/a/program")), &provider(), observation())
            .unwrap()
            .with_caller_input_path("program")
            .unwrap();
        let value = serde_json::to_value(&evidence).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "evidence_id",
                "subject",
                "provider",
                "analysis_profile",
                "predicate_type",
                "operation",
                "parameters",
                "raw_result",
                "normalized_result",
                "confidence",
                "authority",
                "environment",
                "limitations",
                "relationship_coverage",
                "locations",
                "evidence_links",
                "caller_input_path",
            ]
        );
        let subject_keys: Vec<&str> = value["subject"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            subject_keys,
            ["name", "digest", "local_path", "format", "architecture"]
        );
        let parsed: Evidence = serde_json::from_value(value).unwrap();
        parsed.verify().unwrap();
    }

    #[test]
    fn gamecube_and_raw_only_architectures_are_constrained() {
        assert!(SubjectFormat::RawBinary.admits(Some(BinaryArchitecture::M68k)));
        assert!(!SubjectFormat::Elf.admits(Some(BinaryArchitecture::M68k)));
        assert!(!SubjectFormat::GamecubeDol.admits(None));
        assert!(SubjectFormat::GamecubeDol.admits(Some(BinaryArchitecture::PowerPc)));
    }
}
