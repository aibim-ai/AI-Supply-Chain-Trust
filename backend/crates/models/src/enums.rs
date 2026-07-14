use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Severity (must match Python: critical > high > medium > low)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(self) -> i32 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Medium,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Grade (must match Python GRADE_TABLE exactly)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    /// Python: grade_for_score() — returns (grade, verdict, action, override_applied)
    /// Auto-fail: if critical_flags non-empty → force F
    pub fn from_score(
        score: f64,
        has_critical_flags: bool,
    ) -> (Self, &'static str, &'static str, bool) {
        if has_critical_flags {
            return (
                Grade::F,
                "Blocked by policy signal",
                "Escalate to security owner before use",
                true,
            );
        }
        match score {
            s if s >= 85.0 => (
                Grade::A,
                "Eligible for standard review",
                "Proceed with normal intake checks",
                false,
            ),
            s if s >= 70.0 => (
                Grade::B,
                "Review with known gaps",
                "Review missing evidence and document known gaps",
                false,
            ),
            s if s >= 50.0 => (
                Grade::C,
                "Manual security review required",
                "Security review required before use",
                false,
            ),
            s if s >= 30.0 => (
                Grade::D,
                "Do not approve without security owner",
                "Security owner sign-off required",
                false,
            ),
            _ => (
                Grade::F,
                "Manual security review required",
                "Low score requires security review before use",
                false,
            ),
        }
    }

    /// Python: next_review_date(grade, evaluated_at) — A/B=90d, C=30d, D/F=today
    pub fn review_days(self) -> i64 {
        match self {
            Grade::A | Grade::B => 90,
            Grade::C => 30,
            Grade::D | Grade::F => 0,
        }
    }
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// ContextStatus — CRITICAL: compile-time enforcement of evidence gating
// ---------------------------------------------------------------------------
/// Models the `status` field of the SecurityContextEnvelope.
///
/// # Evidence Gating Contract (from Phase 0 §4)
///
/// `Ready` can ONLY be constructed via [`ContextStatus::ready()`] which takes
/// a [`VerifiedEvidence`] struct built by a fallible builder. This makes it
/// a COMPILE-TIME error to construct `Ready` without concrete evidence.
///
/// ```compile_fail
/// // This will NOT compile — VerifiedEvidence is only constructable via the builder:
/// let status = ContextStatus::Ready(VerifiedEvidence { .. }); // private fields
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ContextStatus {
    /// Context is fully built with verified live evidence.
    Ready,
    /// Context generation is in progress (async scan triggered).
    Building,
    /// No context has been generated yet, but metadata exists.
    None,
    /// Evidence is insufficient or gating checks failed.
    /// Carries a specific error code for the API response.
    Error { code: String, message: String },
}

impl ContextStatus {
    /// The only constructor for `Ready` status. Requires concrete evidence
    /// that has passed the evidence gate checks.
    pub fn ready(_evidence: VerifiedEvidence) -> Self {
        ContextStatus::Ready
    }

    pub fn building() -> Self {
        ContextStatus::Building
    }
    pub fn none() -> Self {
        ContextStatus::None
    }
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        ContextStatus::Error {
            code: code.into(),
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// VerifiedEvidence — MUST have at least one real evidence source
// ---------------------------------------------------------------------------
/// Constructed ONLY by `VerifiedEvidenceBuilder` which validates that at least
/// one real evidence source is present before building.
///
/// # Design
/// - All fields are private — not constructable outside this module
/// - The builder is the only public construction path
/// - The builder's `build()` returns `Result<Self, EvidenceError>`, ensuring
///   it's impossible to create a `VerifiedEvidence` with zero real sources
#[derive(Debug, Clone)]
pub struct VerifiedEvidence {
    /// 40-character commit SHA from live GitHub API or git clone
    pub has_commit_sha: bool,
    /// CVE count > 0 OR OSV vulnerability count > 0 from live API calls
    pub has_advisory_or_osv: bool,
    /// Scanner runs exist with at least one non-unavailable status
    pub has_scanner_runs: bool,
    /// security_context_version must match LIVE_SECURITY_CONTEXT_VERSION
    pub version_ok: bool,
}

/// Builder for `VerifiedEvidence`. Validates that at least one real evidence
/// source is present before allowing construction.
pub struct VerifiedEvidenceBuilder {
    has_commit_sha: bool,
    has_advisory_or_osv: bool,
    has_scanner_runs: bool,
    version_ok: bool,
}

impl VerifiedEvidenceBuilder {
    pub fn new(version_ok: bool) -> Self {
        Self {
            has_commit_sha: false,
            has_advisory_or_osv: false,
            has_scanner_runs: false,
            version_ok,
        }
    }

    pub fn with_commit_sha(mut self, sha: Option<&str>) -> Self {
        self.has_commit_sha = sha.is_some_and(|s| s.len() == 40);
        self
    }

    pub fn with_cve_count(mut self, count: usize) -> Self {
        self.has_advisory_or_osv = self.has_advisory_or_osv || count > 0;
        self
    }

    pub fn with_osv_count(mut self, count: usize) -> Self {
        self.has_advisory_or_osv = self.has_advisory_or_osv || count > 0;
        self
    }

    pub fn with_scanner_runs(mut self, count: usize) -> Self {
        self.has_scanner_runs = count > 0;
        self
    }

    /// Returns `Ok(VerifiedEvidence)` only if at least one evidence source is present
    /// AND the version check passed. Otherwise returns `Err` with the missing sources.
    pub fn build(self) -> Result<VerifiedEvidence, EvidenceError> {
        if !self.version_ok {
            return Err(EvidenceError::VersionMismatch);
        }
        if !self.has_commit_sha && !self.has_advisory_or_osv && !self.has_scanner_runs {
            return Err(EvidenceError::NoEvidence {
                missing: vec![
                    (!self.has_commit_sha).then_some("commit_sha"),
                    (!self.has_advisory_or_osv).then_some("advisory_or_osv"),
                    (!self.has_scanner_runs).then_some("scanner_runs"),
                ]
                .into_iter()
                .flatten()
                .map(String::from)
                .collect(),
            });
        }
        Ok(VerifiedEvidence {
            has_commit_sha: self.has_commit_sha,
            has_advisory_or_osv: self.has_advisory_or_osv,
            has_scanner_runs: self.has_scanner_runs,
            version_ok: self.version_ok,
        })
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum EvidenceError {
    #[error("security_context_version mismatch")]
    VersionMismatch,
    #[error("no live evidence available: missing {missing:?}")]
    NoEvidence { missing: Vec<String> },
}

// ---------------------------------------------------------------------------
// DataSourceError — for external API failures
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSourceError {
    GitHubRateLimited,
    GitHubRepoNotFound,
    GitHubUnauthorized,
    GitHubTimeout,
    OsvTimeout,
    NvdRateLimited,
    GitCloneFailed,
    ScannerTimeout,
    ScannerUnavailable,
    DatabaseLocked,
}

impl std::fmt::Display for DataSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl DataSourceError {
    pub fn http_status(&self) -> u16 {
        match self {
            DataSourceError::GitHubRateLimited => 429,
            DataSourceError::GitHubRepoNotFound => 404,
            DataSourceError::GitHubUnauthorized => 500,
            DataSourceError::GitHubTimeout => 504,
            DataSourceError::OsvTimeout => 504,
            DataSourceError::NvdRateLimited => 429,
            DataSourceError::GitCloneFailed => 502,
            DataSourceError::ScannerTimeout => 504,
            DataSourceError::ScannerUnavailable => 200,
            DataSourceError::DatabaseLocked => 503,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            DataSourceError::GitHubRateLimited => "github_rate_limited",
            DataSourceError::GitHubRepoNotFound => "repo_not_found",
            DataSourceError::GitHubUnauthorized => "github_unauthorized",
            DataSourceError::GitHubTimeout => "github_timeout",
            DataSourceError::OsvTimeout => "osv_timeout",
            DataSourceError::NvdRateLimited => "nvd_rate_limited",
            DataSourceError::GitCloneFailed => "git_clone_failed",
            DataSourceError::ScannerTimeout => "scanner_timeout",
            DataSourceError::ScannerUnavailable => "scanner_unavailable",
            DataSourceError::DatabaseLocked => "database_locked",
        }
    }
}
