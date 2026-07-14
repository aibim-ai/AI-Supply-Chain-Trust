//! Trust signals — matches `trust_signals.py`.
//! Star growth analysis, dependency manifest analysis, license signals.

use ai_supply_chain_trust_models::{Finding, Severity};

/// Analyze star growth pattern for fake-star detection.
pub fn analyze_star_signals(stars: i64, account_age_days: i64) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Very high star count on very new account → suspicious
    if stars > 100 && account_age_days < 30 {
        findings.push(Finding::new(
            "rapid_star_growth",
            Severity::High,
            format!("{stars} stars on account only {account_age_days} days old — possible purchased/fake stars."),
        ));
    }
    // Extreme ratio
    if stars > 1000 && account_age_days < 90 {
        findings.push(Finding::new(
            "extreme_star_growth",
            Severity::Medium,
            format!("{stars} stars in {account_age_days} days — unusual growth pattern."),
        ));
    }
    findings
}

/// Analyze repository license signals.
pub fn analyze_license_signals(license: Option<&str>) -> Vec<Finding> {
    let mut findings = Vec::new();
    match license {
        None | Some("") | Some("NOASSERTION") | Some("Other") => {
            findings.push(Finding::new(
                "missing_license",
                Severity::Medium,
                "No recognized open-source license detected.",
            ));
        }
        Some(l)
            if l.to_lowercase().contains("proprietary")
                || l.to_lowercase().contains("commercial") =>
        {
            findings.push(Finding::new(
                "restrictive_license",
                Severity::Low,
                format!("License '{l}' may restrict usage — review terms."),
            ));
        }
        Some(l) if !is_osi_approved(l) => {
            findings.push(Finding::new(
                "non_osi_license",
                Severity::Low,
                format!("License '{l}' is not OSI-approved."),
            ));
        }
        _ => {}
    }
    findings
}

fn is_osi_approved(license: &str) -> bool {
    matches!(
        license.to_lowercase().as_str(),
        "mit"
            | "apache-2.0"
            | "bsd-2-clause"
            | "bsd-3-clause"
            | "gpl-2.0"
            | "gpl-3.0"
            | "lgpl-2.1"
            | "lgpl-3.0"
            | "mpl-2.0"
            | "isc"
            | "unlicense"
            | "cc0-1.0"
            | "artistic-2.0"
            | "epl-2.0"
            | "agpl-3.0"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_growth_on_new_account_flagged() {
        let f = analyze_star_signals(200, 10);
        assert!(!f.is_empty());
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn established_account_no_flag() {
        let f = analyze_star_signals(5000, 365);
        assert!(f.is_empty());
    }

    #[test]
    fn missing_license_flagged() {
        let f = analyze_license_signals(None);
        assert!(!f.is_empty());
    }

    #[test]
    fn mit_license_clean() {
        let f = analyze_license_signals(Some("MIT"));
        assert!(f.is_empty());
    }
}
