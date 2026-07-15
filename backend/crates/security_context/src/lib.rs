//! Security Context generation — matches `security_context.py` exactly.

pub mod context;
pub mod envelope;
pub mod evidence;
pub mod fingerprints;
pub mod leads;
pub mod regression_contracts;
pub mod render;
pub mod top_risks;

pub use context::context_from_report;
pub use envelope::envelope_from_report;
pub use evidence::{has_ready_evidence, ready_evidence_summary, LIVE_SECURITY_CONTEXT_VERSION};
pub use fingerprints::fingerprints_from_report;
pub use leads::leads_from_report;
pub use regression_contracts::regression_contracts_from_report;
pub use render::{render_context_markdown, render_leads_markdown};
pub use top_risks::top_risks;
