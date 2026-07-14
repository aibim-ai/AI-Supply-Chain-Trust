use super::Severity;
use serde::{Deserialize, Serialize};

/// Matches `models.py:Finding(code, severity, message, evidence, location, automatic_fail)`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(default)]
    pub automatic_fail: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc: Option<String>,
}

impl Finding {
    pub fn new(code: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity,
            message: message.into(),
            evidence: String::new(),
            location: String::new(),
            automatic_fail: false,
            commit_sha: None,
            commit_date: None,
            commit_subject: None,
            cwe: Vec::new(),
            poc: None,
        }
    }

    pub fn with_automatic_fail(mut self) -> Self {
        self.automatic_fail = true;
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = evidence.into();
        self
    }
}
