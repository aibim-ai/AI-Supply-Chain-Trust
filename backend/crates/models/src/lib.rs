//! Pure data models matching `models.py` exactly.
//! No I/O, no side effects, no business logic — only data shapes.
//!
//! Every struct here maps 1:1 to the Python dataclass `to_dict()` output.
//! Serde `rename_all = "snake_case"` ensures JSON output is identical.
//!
//! #![deny(unreachable_patterns)] — enforced at crate level.

#![deny(unreachable_patterns)]

pub mod context;
pub mod enums;
pub mod finding;
pub mod pillar;
pub mod report;
pub mod scanner;

pub use context::{
    ContextArtifacts, ContextSummary, EvidenceGate, Fingerprint, Remediation, RepoRef,
    SecurityContext, SecurityContextEnvelope, SharedSurface, TopRisk, TrustMetrics,
    VulnerabilityLeads,
};
pub use enums::*;
pub use finding::Finding;
pub use pillar::PillarResult;
pub use report::EvaluationResult;
pub use scanner::ScannerRun;
