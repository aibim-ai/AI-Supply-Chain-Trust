use serde::{Deserialize, Serialize};

/// Matches `models.py` scanner_runs entry: `{"tool", "status", "detail", "impact"}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerRun {
    pub tool: String,
    pub status: ScannerStatus,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScannerStatus {
    Ok,
    Skipped,
    Partial,
    Failed,
    Unavailable,
}

impl std::fmt::Display for ScannerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ScannerStatus::Ok => "ok",
            ScannerStatus::Skipped => "skipped",
            ScannerStatus::Partial => "partial",
            ScannerStatus::Failed => "failed",
            ScannerStatus::Unavailable => "unavailable",
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_status_display_and_json_contracts_cover_every_state() {
        let cases = [
            (ScannerStatus::Ok, "ok"),
            (ScannerStatus::Skipped, "skipped"),
            (ScannerStatus::Partial, "partial"),
            (ScannerStatus::Failed, "failed"),
            (ScannerStatus::Unavailable, "unavailable"),
        ];
        for (status, expected) in cases {
            assert_eq!(status.to_string(), expected);
            assert_eq!(
                serde_json::to_string(&status).unwrap(),
                format!("\"{expected}\"")
            );
        }
    }

    #[test]
    fn scanner_run_round_trips_optional_impact() {
        let run = ScannerRun {
            tool: "semgrep".into(),
            status: ScannerStatus::Partial,
            detail: "2 findings".into(),
            impact: Some("review".into()),
        };
        let encoded = serde_json::to_string(&run).unwrap();
        let decoded: ScannerRun = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded.tool, "semgrep");
        assert_eq!(decoded.status, ScannerStatus::Partial);
        assert_eq!(decoded.impact.as_deref(), Some("review"));
    }
}
