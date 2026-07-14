//! OpenRouter-backed LLM integration and mandatory output guardrails.
//!
//! Production callers should use the task helpers or `LlmGuardrail`; direct
//! OpenRouter calls outside this crate bypass evidence validation.

pub mod fact_checker;
pub mod guardrail;
pub mod llm_client;
pub mod tasks;

pub use fact_checker::{FactCheckError, FactCheckResult};
pub use guardrail::{GuardrailError, LlmGuardrail};
pub use llm_client::{
    runtime_telemetry_snapshot, LlmCallResult, LlmClient, LlmClientConfig, LlmUnavailableError,
};
