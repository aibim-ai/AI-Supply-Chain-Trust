use super::esc;
use super::repo_to_path;
use serde_json::Value;

pub fn render_home() -> (String, String) {
    let head = super::head::build_head(
        "AI Supply Chain Trust — Free repository scanner",
        "Scan AI repositories and model supply chains.",
        "/",
        "https://ai-supply-chain-trust.aibim.ai",
        true,
        "",
    );
    let main = r#"<section class="scan-home">
      <h1>AI Supply Chain Trust</h1>
      <p>Paste a GitHub repo to get a trust score, critical flags, and a reusable report.</p>
      <form><input type="text" placeholder="owner/repo"><button>Scan</button></form>
    </section>"#
        .to_string();
    (head, main)
}

pub fn render_leaderboard(rows: &[Value]) -> (String, String) {
    let head = super::head::build_head(
        "Leaderboard | AI Supply Chain Trust",
        "Ranked repository trust scores.",
        "/leaderboard",
        "https://ai-supply-chain-trust.aibim.ai",
        true,
        "",
    );
    let rows_html: String = rows
        .iter()
        .map(|r| {
            let repo = r.get("repo").and_then(Value::as_str).unwrap_or("");
            let score = r.get("trust_score").and_then(Value::as_f64).unwrap_or(0.0) as i64;
            let grade = r.get("grade").and_then(Value::as_str).unwrap_or("-");
            format!(
                "<tr><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td></tr>",
                esc(&repo_to_path(repo)),
                esc(repo),
                score,
                esc(grade)
            )
        })
        .collect();

    let main = format!(
        r#"<section class="page-stack"><h1>Leaderboard</h1>
        <table><thead><tr><th>Repository</th><th>Score</th><th>Grade</th></tr></thead>
        <tbody>{rows_html}</tbody></table></section>"#
    );
    (head, main)
}

pub fn render_result(report: &Value) -> (String, String) {
    let repo = report.get("repo").and_then(Value::as_str).unwrap_or("");
    let score = report
        .get("trust_score")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let grade = report.get("grade").and_then(Value::as_str).unwrap_or("-");
    let verdict = report.get("verdict").and_then(Value::as_str).unwrap_or("");
    let evaluated = report
        .get("evaluated_at")
        .and_then(Value::as_str)
        .unwrap_or("");

    let head = super::head::build_head(
        &format!("{repo} result | AI Supply Chain Trust"),
        &format!("{repo} scored {score:.0}/100 (grade {grade}, {verdict})."),
        &repo_to_path(repo),
        "https://ai-supply-chain-trust.aibim.ai",
        false,
        "",
    );

    let badge = score_badge(report);
    let main = format!(
        r#"<section class="page-stack">
        <div class="result-header">
          <h1>{}</h1>
          <p>{} · Evaluated {}</p>
          <div class="result-score">{}</div>
        </div></section>"#,
        esc(repo),
        esc(verdict),
        esc(evaluated),
        badge
    );
    (head, main)
}

fn score_badge(report: &Value) -> String {
    let score = report
        .get("trust_score")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        .round() as i64;
    let grade = report.get("grade").and_then(Value::as_str).unwrap_or("-");
    let tone = match grade {
        "A" => "success",
        "B" => "warning",
        "C" => "high-risk",
        "D" | "F" => "danger",
        _ => "info",
    };
    format!(
        r#"<span class="score-badge score-{tone}"><strong>{score}</strong><em>{grade}</em></span>"#
    )
}
