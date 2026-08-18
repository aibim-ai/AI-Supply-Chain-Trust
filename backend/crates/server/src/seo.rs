//! Server-side `<head>` (and minimal `<body>`) metadata for the SPA shell.
//!
//! The shipped shell carries a `<!--SSR_HEAD-->` placeholder plus a *generic*
//! `<title>` and `meta[name="description"]` that are emitted by `vite build`
//! before that placeholder. Appending route metadata at the placeholder would
//! therefore leave two of each, generic one first — which is what crawlers and
//! link unfurlers read. So the injection strips every managed identity out of
//! the shell's `<head>` first and re-emits exactly one of each.
//!
//! The identities below are the same ones `frontend/src/lib/seo.js` resolves
//! and rewrites in place on hydration, so the tag set must match exactly:
//!
//! * `<title>`
//! * `link[rel="canonical"]`
//! * `meta[name="description"]`
//! * `meta[name="robots"]` — only on the 404 route; the client removes it
//!   everywhere else
//! * `meta[property="og:title" | "og:description" | "og:url" | "og:type" |
//!   "og:site_name"]`
//! * `meta[name="twitter:card" | "twitter:title" | "twitter:description"]`
//! * `script[type="application/ld+json"][data-seo="route"]` — at most one; the
//!   client claims the first and deletes any others
//!
//! Every value is HTML-escaped, and repository slugs arrive from a URL path, so
//! they are treated as untrusted input throughout.

use serde_json::{json, Value};

pub(crate) const SITE_NAME: &str = "AI Supply Chain Trust";

const HEAD_PLACEHOLDER: &str = "<!--SSR_HEAD-->";
const MAIN_PLACEHOLDER: &str = "<!--SSR_MAIN-->";

const HOME_DESCRIPTION: &str = "Scan any public GitHub repository for a traceable security context: repository history, disclosed CVEs, missing evidence, and ranked review leads.";
const CONTEXTS_DESCRIPTION: &str = "Browse every published security context and queued scan: trust grades, evidence coverage, fixes, and disclosed CVEs for public GitHub repositories.";
const LEADERBOARD_DESCRIPTION: &str = "Compare stored trust verdicts for public GitHub repositories by score, grade, evidence coverage, and review age.";
const RESULT_DESCRIPTION: &str = "Open a stored trust verdict for a public GitHub repository, with evidence coverage, scanner runs, and score history.";
const NOT_FOUND_DESCRIPTION: &str = "This page does not exist. Browse published repository security contexts or scan a public GitHub repository.";
const ABOUT_DESCRIPTION: &str = "How AI Supply Chain Trust turns public repository evidence into reusable, traceable review context for people and coding agents.";
const POLICY_DESCRIPTION: &str = "How reports separate observed evidence, derived signals, and unavailable data — and what they deliberately do not claim.";
const PRIVACY_DESCRIPTION: &str = "What AI Supply Chain Trust collects: public repository inputs only, public cacheable results, and analytics that start only after consent.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegalPage {
    About,
    EditorialPolicy,
    Privacy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpaRoute {
    Home,
    Contexts,
    Leaderboard,
    Result { repository: Option<String> },
    Repository { repository: String },
    Legal(LegalPage),
    NotFound { path: String },
}

/// Maps a request path (and query) onto the client router in
/// `frontend/src/app/router.jsx`. Anything the router does not name renders
/// `NotFoundPage`, so it is described as the 404 here too.
pub(crate) fn resolve_route(path: &str, query: Option<&str>) -> SpaRoute {
    let trimmed = path.trim_end_matches('/');
    match trimmed {
        "" => SpaRoute::Home,
        "/contexts" => SpaRoute::Contexts,
        "/leaderboard" => SpaRoute::Leaderboard,
        "/about" => SpaRoute::Legal(LegalPage::About),
        "/editorial-policy" => SpaRoute::Legal(LegalPage::EditorialPolicy),
        "/privacy" => SpaRoute::Legal(LegalPage::Privacy),
        "/result" => SpaRoute::Result {
            repository: query.and_then(query_repository),
        },
        _ => match trimmed.strip_prefix("/r/") {
            // The path arrives raw here but percent-decoded through the
            // `/r/*path` route's `Path` extractor, so both spellings resolve to
            // the same repository.
            Some(repository) if repository.split('/').count() == 2 => {
                let segments = repository
                    .split('/')
                    .map(percent_decode)
                    .collect::<Vec<_>>();
                if segments
                    .iter()
                    .all(|part| !part.trim().is_empty() && !part.contains('/'))
                {
                    SpaRoute::Repository {
                        repository: segments.join("/"),
                    }
                } else {
                    SpaRoute::NotFound {
                        path: path.to_string(),
                    }
                }
            }
            _ => SpaRoute::NotFound {
                path: path.to_string(),
            },
        },
    }
}

/// The repository whose stored report describes this route, if any.
pub(crate) fn route_repository(route: &SpaRoute) -> Option<&str> {
    match route {
        SpaRoute::Repository { repository } => Some(repository.as_str()),
        SpaRoute::Result { repository } => repository.as_deref(),
        _ => None,
    }
}

fn query_repository(query: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if key != "repo" {
            return None;
        }
        let decoded = percent_decode(value);
        if decoded.trim().is_empty() {
            None
        } else {
            Some(decoded)
        }
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or_default();
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Mirrors `encodeURIComponent`, which is what the client uses to build the
/// only canonical URL that carries a query (`/result?repo=...`).
fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(*byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Percent-encodes a repository slug for a path segment, keeping the `/`
/// separator readable. Anything that could terminate an attribute or start a
/// tag is encoded here and escaped again on the way into the document.
fn encode_repository_path(value: &str) -> String {
    value
        .split('/')
        .map(encode_uri_component)
        .collect::<Vec<_>>()
        .join("/")
}

fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// JSON-LD lives inside a `<script>`, where HTML escaping would corrupt it.
/// Escaping `<` as `<` keeps `</script>` and `<!--` from terminating the
/// element while staying valid JSON.
fn escape_json_ld(value: &Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "{}".to_string())
        .replace('<', "\\u003c")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn page_title(text: &str) -> String {
    let value = text.trim();
    if value.is_empty() || value == SITE_NAME {
        SITE_NAME.to_string()
    } else {
        format!("{value} | {SITE_NAME}")
    }
}

/// Report fields the head needs, filtered the way the client filters them
/// (`pick()` drops empty strings, `"-"` and `"unknown"`).
struct ReportFacts {
    grade: Option<String>,
    score: Option<f64>,
    verdict: Option<String>,
    action: Option<String>,
    evaluated_at: Option<String>,
}

impl ReportFacts {
    fn from(report: Option<&Value>) -> Self {
        let text = |report: &Value, key: &str| {
            report
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty() && *value != "-" && *value != "unknown")
                .map(str::to_string)
        };
        match report {
            None => Self {
                grade: None,
                score: None,
                verdict: None,
                action: None,
                evaluated_at: None,
            },
            Some(report) => Self {
                grade: text(report, "grade"),
                score: report
                    .get("trust_score")
                    .and_then(Value::as_f64)
                    .filter(|value| value.is_finite()),
                verdict: text(report, "verdict"),
                action: text(report, "action"),
                evaluated_at: text(report, "evaluated_at"),
            },
        }
    }

    /// `trust grade B 75/100` — the badge the client renders in the title.
    fn badge(&self, grade_prefix: &str) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(grade) = &self.grade {
            parts.push(format!("{grade_prefix}{grade}"));
        }
        if let Some(score) = self.score {
            parts.push(format!("{}/100", score.round() as i64));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
}

pub(crate) struct PageMeta {
    title: String,
    description: String,
    canonical: String,
    robots: Option<&'static str>,
    og_type: &'static str,
    json_ld: Option<Value>,
    main_html: String,
}

/// Builds the metadata for one route. `origin` is an absolute scheme+host with
/// no trailing slash; `report` is the stored evaluation when the route names a
/// repository (a repository with no stored report degrades to the generic
/// wording rather than to a broken title).
pub(crate) fn page_meta(route: &SpaRoute, origin: &str, report: Option<&Value>) -> PageMeta {
    let origin = origin.trim_end_matches('/');
    match route {
        SpaRoute::Home => PageMeta {
            title: format!("{SITE_NAME} — public repository security context"),
            description: HOME_DESCRIPTION.to_string(),
            canonical: format!("{origin}/"),
            robots: None,
            og_type: "website",
            json_ld: Some(website_json_ld(origin, HOME_DESCRIPTION)),
            main_html: String::new(),
        },
        SpaRoute::Contexts => PageMeta {
            title: page_title("Public repository contexts"),
            description: CONTEXTS_DESCRIPTION.to_string(),
            canonical: format!("{origin}/contexts"),
            robots: None,
            og_type: "website",
            json_ld: None,
            main_html: String::new(),
        },
        SpaRoute::Leaderboard => PageMeta {
            title: page_title("Repository trust leaderboard"),
            description: LEADERBOARD_DESCRIPTION.to_string(),
            canonical: format!("{origin}/leaderboard"),
            robots: None,
            og_type: "website",
            json_ld: None,
            main_html: String::new(),
        },
        SpaRoute::Legal(page) => {
            let (title, description, path) = match page {
                LegalPage::About => ("About", ABOUT_DESCRIPTION, "/about"),
                LegalPage::EditorialPolicy => {
                    ("Editorial policy", POLICY_DESCRIPTION, "/editorial-policy")
                }
                LegalPage::Privacy => ("Privacy", PRIVACY_DESCRIPTION, "/privacy"),
            };
            PageMeta {
                title: page_title(title),
                description: description.to_string(),
                canonical: format!("{origin}{path}"),
                robots: None,
                og_type: "website",
                json_ld: None,
                main_html: String::new(),
            }
        }
        SpaRoute::Result { repository } => result_meta(origin, repository.as_deref(), report),
        SpaRoute::Repository { repository } => repository_meta(origin, repository, report),
        SpaRoute::NotFound { path } => {
            let path = if path.is_empty() || path == "/" {
                "/".to_string()
            } else {
                path.to_string()
            };
            PageMeta {
                title: page_title("Page not found"),
                description: NOT_FOUND_DESCRIPTION.to_string(),
                canonical: format!("{origin}{}", encode_path(&path)),
                // The only route that carries robots. The client removes this
                // tag on every other route.
                robots: Some("noindex, follow"),
                og_type: "website",
                json_ld: None,
                main_html: String::new(),
            }
        }
    }
}

fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for character in path.chars() {
        match character {
            '/' | '-' | '_' | '.' | '~' => out.push(character),
            c if c.is_ascii_alphanumeric() => out.push(c),
            c => {
                let mut buffer = [0u8; 4];
                for byte in c.encode_utf8(&mut buffer).as_bytes() {
                    out.push_str(&format!("%{byte:02X}"));
                }
            }
        }
    }
    out
}

fn result_meta(origin: &str, repository: Option<&str>, report: Option<&Value>) -> PageMeta {
    let Some(repository) = repository else {
        return PageMeta {
            title: page_title("Trust verdict"),
            description: RESULT_DESCRIPTION.to_string(),
            canonical: format!("{origin}/result"),
            robots: None,
            og_type: "website",
            json_ld: None,
            main_html: String::new(),
        };
    };
    let facts = ReportFacts::from(report);
    let badge = facts.badge("grade ");
    let title = match &badge {
        Some(badge) => page_title(&format!("{repository} trust verdict — {badge}")),
        None => page_title(&format!("{repository} trust verdict")),
    };
    let description = [
        facts
            .verdict
            .clone()
            .unwrap_or_else(|| format!("Stored trust verdict for {repository}")),
        badge.map(|badge| format!("({badge})")).unwrap_or_default(),
        "with evidence coverage, scanner runs, and score history.".to_string(),
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(" ");

    PageMeta {
        title,
        description,
        canonical: format!(
            "{origin}/result?repo={}",
            encode_uri_component(repository.trim())
        ),
        robots: None,
        og_type: "website",
        json_ld: None,
        main_html: String::new(),
    }
}

fn repository_meta(origin: &str, repository: &str, report: Option<&Value>) -> PageMeta {
    let url = format!("{origin}/r/{}", encode_repository_path(repository));
    let facts = ReportFacts::from(report);
    let badge = facts.badge("trust grade ");
    let title = match &badge {
        Some(badge) => page_title(&format!("{repository} — {badge}")),
        None => page_title(&format!("{repository} security context")),
    };
    let description = match (&facts.verdict, &badge) {
        (Some(verdict), Some(badge)) => format!(
            "{verdict} ({badge}) — evidence-backed security context for {repository}: disclosed CVEs, missing evidence, and ranked review leads."
        ),
        (Some(verdict), None) => format!(
            "{verdict} — evidence-backed security context for {repository}: disclosed CVEs, missing evidence, and ranked review leads."
        ),
        _ => format!(
            "Evidence-backed security context for the public GitHub repository {repository}: disclosed CVEs, missing evidence, and ranked review leads."
        ),
    };

    PageMeta {
        title,
        description,
        canonical: url.clone(),
        robots: None,
        og_type: "article",
        json_ld: Some(repository_json_ld(origin, repository, &url, &facts)),
        main_html: repository_main_html(repository, &facts),
    }
}

/// Minimal crawlable body content for the repository route.
///
/// `frontend/src/main.jsx` mounts with `createRoot(...).render(...)`, i.e. a
/// client render rather than `hydrateRoot`, so React discards whatever is in
/// `#root` on mount: no hydration mismatch is possible. The block is therefore
/// kept to a heading, one sentence and one link — enough for a crawler or an
/// unfurler that never runs the bundle, small enough that the pre-mount frame
/// reads as a plain stub instead of a flash of a half-built page.
fn repository_main_html(repository: &str, facts: &ReportFacts) -> String {
    let label = escape_html(repository);
    let href = escape_html(&format!(
        "https://github.com/{}",
        encode_repository_path(repository)
    ));
    let verdict = facts
        .verdict
        .as_deref()
        .map(|verdict| {
            let verdict = escape_html(verdict);
            if verdict.ends_with(['.', '!', '?']) {
                verdict
            } else {
                format!("{verdict}.")
            }
        })
        .unwrap_or_else(|| "No published trust verdict yet.".to_string());
    let mut summary = vec![verdict];
    if let Some(grade) = &facts.grade {
        summary.push(format!("Trust grade {}.", escape_html(grade)));
    }
    if let Some(score) = facts.score {
        summary.push(format!("Trust score {}/100.", score.round() as i64));
    }
    format!(
        "<article><h1>{label} security context</h1><p>{}</p><p><a href=\"{href}\">github.com/{label}</a></p></article>",
        summary.join(" ")
    )
}

fn website_json_ld(origin: &str, description: &str) -> Value {
    json!([
        {
            "@context": "https://schema.org",
            "@type": "WebSite",
            "@id": format!("{origin}/#website"),
            "name": SITE_NAME,
            "url": format!("{origin}/"),
            "description": description,
            "publisher": {"@id": format!("{origin}/#organization")}
        },
        {
            "@context": "https://schema.org",
            "@type": "Organization",
            "@id": format!("{origin}/#organization"),
            "name": "AIBIM",
            "url": format!("{origin}/"),
            "logo": format!("{origin}/aibim-logo.svg"),
            "brand": SITE_NAME
        }
    ])
}

fn repository_json_ld(origin: &str, repository: &str, url: &str, facts: &ReportFacts) -> Value {
    let mut node = json!({
        "@context": "https://schema.org",
        "@type": "SoftwareSourceCode",
        "name": repository,
        "codeRepository": format!("https://github.com/{repository}"),
        "url": url,
    });
    if let Some(verdict) = &facts.verdict {
        node["description"] = json!(verdict);
    }

    let mut rating = serde_json::Map::new();
    if let Some(score) = facts.score {
        rating.insert("@type".into(), json!("Rating"));
        rating.insert("ratingValue".into(), json!(score.round() as i64));
        rating.insert("bestRating".into(), json!(100));
        rating.insert("worstRating".into(), json!(0));
    }
    if let Some(grade) = &facts.grade {
        rating.insert("@type".into(), json!("Rating"));
        rating.insert("alternateName".into(), json!(grade));
    }
    let review_body = [facts.verdict.as_deref(), facts.action.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" — ");

    if !rating.is_empty() || !review_body.is_empty() {
        let mut review = json!({
            "@type": "Review",
            "name": format!("{repository} trust verdict"),
            "url": url,
            "author": {
                "@type": "Organization",
                "name": SITE_NAME,
                "url": format!("{origin}/")
            }
        });
        if !review_body.is_empty() {
            review["reviewBody"] = json!(review_body);
        }
        if let Some(evaluated_at) = &facts.evaluated_at {
            review["datePublished"] = json!(evaluated_at);
        }
        if !rating.is_empty() {
            review["reviewRating"] = Value::Object(rating);
        }
        node["subjectOf"] = review;
    }
    node
}

impl PageMeta {
    /// Renders exactly one tag per managed identity.
    fn render_head(&self) -> String {
        let title = escape_html(&self.title);
        let description = escape_html(&self.description);
        let canonical = escape_html(&self.canonical);
        let mut head = String::new();
        head.push_str(&format!("<title>{title}</title>\n    "));
        head.push_str(&format!(
            "<link rel=\"canonical\" href=\"{canonical}\" />\n    "
        ));
        head.push_str(&format!(
            "<meta name=\"description\" content=\"{description}\" />\n    "
        ));
        if let Some(robots) = self.robots {
            head.push_str(&format!(
                "<meta name=\"robots\" content=\"{robots}\" />\n    "
            ));
        }
        head.push_str(&format!(
            "<meta property=\"og:title\" content=\"{title}\" />\n    "
        ));
        head.push_str(&format!(
            "<meta property=\"og:description\" content=\"{description}\" />\n    "
        ));
        head.push_str(&format!(
            "<meta property=\"og:url\" content=\"{canonical}\" />\n    "
        ));
        head.push_str(&format!(
            "<meta property=\"og:type\" content=\"{}\" />\n    ",
            self.og_type
        ));
        head.push_str(&format!(
            "<meta property=\"og:site_name\" content=\"{}\" />\n    ",
            escape_html(SITE_NAME)
        ));
        head.push_str("<meta name=\"twitter:card\" content=\"summary\" />\n    ");
        head.push_str(&format!(
            "<meta name=\"twitter:title\" content=\"{title}\" />\n    "
        ));
        head.push_str(&format!(
            "<meta name=\"twitter:description\" content=\"{description}\" />"
        ));
        if let Some(json_ld) = &self.json_ld {
            head.push_str(&format!(
                "\n    <script type=\"application/ld+json\" data-seo=\"route\">{}</script>",
                escape_json_ld(json_ld)
            ));
        }
        head
    }
}

/// Injects route metadata into the served shell.
///
/// Never fails: a shell without the placeholders, or with the managed tags
/// formatted differently by a future `vite build`, still comes back as a
/// serveable document.
pub(crate) fn render_document(
    shell: &str,
    route: &SpaRoute,
    origin: &str,
    report: Option<&Value>,
) -> String {
    let meta = page_meta(route, origin, report);
    let (head_source, rest) = split_head(shell);
    let mut document = String::with_capacity(shell.len() + 1024);
    document.push_str(&strip_managed_head_tags(head_source));
    document.push_str(rest);

    let head = meta.render_head();
    if document.contains(HEAD_PLACEHOLDER) {
        document = document.replacen(HEAD_PLACEHOLDER, &head, 1);
    } else if let Some(index) = find_ignore_ascii_case(&document, "</head>") {
        document.insert_str(index, &format!("{head}\n  "));
    } else {
        document.insert_str(0, &head);
    }

    if document.contains(MAIN_PLACEHOLDER) {
        document = document.replacen(MAIN_PLACEHOLDER, &meta.main_html, 1);
    }
    document
}

/// Everything up to and including `</head>`, plus the remainder. Managed tags
/// are only ever stripped from the head, so a JSON-LD block in the body (there
/// is none today) would survive untouched.
fn split_head(html: &str) -> (&str, &str) {
    match find_ignore_ascii_case(html, "</head>") {
        Some(index) => html.split_at(index),
        None => (html, ""),
    }
}

fn find_ignore_ascii_case(haystack: &str, needle: &str) -> Option<usize> {
    let haystack_lower = haystack.to_ascii_lowercase();
    haystack_lower.find(&needle.to_ascii_lowercase())
}

/// Removes every tag whose identity this module re-emits, whatever the
/// attribute order, quoting or line wrapping the build happens to produce.
fn strip_managed_head_tags(head: &str) -> String {
    let bytes = head.as_bytes();
    let mut out = String::with_capacity(head.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'<' {
            let next = head[index..]
                .find('<')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            out.push_str(&head[index..next]);
            index = next;
            continue;
        }
        let Some((name, attributes, tag_end)) = parse_tag(head, index) else {
            out.push('<');
            index += 1;
            continue;
        };
        let managed = match name.as_str() {
            "title" => true,
            "meta" => is_managed_meta(&attributes),
            "link" => attribute(&attributes, "rel")
                .map(|rel| rel.eq_ignore_ascii_case("canonical"))
                .unwrap_or(false),
            "script" => attribute(&attributes, "type")
                .map(|value| value.trim().eq_ignore_ascii_case("application/ld+json"))
                .unwrap_or(false),
            _ => false,
        };
        if !managed {
            out.push_str(&head[index..tag_end]);
            index = tag_end;
            continue;
        }
        // Elements with text content are dropped together with that content.
        index = match name.as_str() {
            "title" | "script" => {
                let closing = format!("</{name}");
                match find_ignore_ascii_case(&head[tag_end..], &closing) {
                    Some(offset) => {
                        let close_start = tag_end + offset;
                        match head[close_start..].find('>') {
                            Some(end) => close_start + end + 1,
                            None => head.len(),
                        }
                    }
                    None => tag_end,
                }
            }
            _ => tag_end,
        };
        // Drop trailing whitespace left behind so the head does not grow blank
        // lines on every release.
        while out.ends_with(' ') {
            out.pop();
        }
        if out.ends_with('\n') {
            while index < bytes.len() && (bytes[index] == b' ' || bytes[index] == b'\t') {
                index += 1;
            }
            if index < bytes.len() && bytes[index] == b'\n' {
                index += 1;
            }
        }
    }
    out
}

fn is_managed_meta(attributes: &[(String, String)]) -> bool {
    if let Some(name) = attribute(attributes, "name") {
        let name = name.trim().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "description" | "robots" | "twitter:card" | "twitter:title" | "twitter:description"
        ) {
            return true;
        }
    }
    attribute(attributes, "property")
        .map(|property| property.trim().to_ascii_lowercase().starts_with("og:"))
        .unwrap_or(false)
}

fn attribute<'a>(attributes: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
}

/// Lowercased element name, its attributes, and the index just past `>`.
type ParsedTag = (String, Vec<(String, String)>, usize);

/// Parses the tag starting at `start` (`html[start] == '<'`).
fn parse_tag(html: &str, start: usize) -> Option<ParsedTag> {
    let bytes = html.as_bytes();
    let mut index = start + 1;
    if index >= bytes.len() || !bytes[index].is_ascii_alphabetic() {
        return None;
    }
    let name_start = index;
    while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'-') {
        index += 1;
    }
    let name = html[name_start..index].to_ascii_lowercase();

    let mut attributes = Vec::new();
    loop {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            return None;
        }
        if bytes[index] == b'>' {
            return Some((name, attributes, index + 1));
        }
        if bytes[index] == b'/' {
            index += 1;
            continue;
        }
        let key_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && bytes[index] != b'='
            && bytes[index] != b'>'
            && bytes[index] != b'/'
        {
            index += 1;
        }
        if index == key_start {
            index += 1;
            continue;
        }
        let key = html[key_start..index].to_string();
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b'=' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index >= bytes.len() {
                return None;
            }
            let value = match bytes[index] {
                quote @ (b'"' | b'\'') => {
                    index += 1;
                    let value_start = index;
                    while index < bytes.len() && bytes[index] != quote {
                        index += 1;
                    }
                    let value = html[value_start..index.min(html.len())].to_string();
                    index = (index + 1).min(bytes.len());
                    value
                }
                _ => {
                    let value_start = index;
                    while index < bytes.len()
                        && !bytes[index].is_ascii_whitespace()
                        && bytes[index] != b'>'
                    {
                        index += 1;
                    }
                    html[value_start..index].to_string()
                }
            };
            attributes.push((key, value));
        } else {
            attributes.push((key, String::new()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHELL: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <meta
      name="description"
      content="Agent-ready security context for public software repositories."
    />
    <link rel="icon" href="./favicon.svg" type="image/svg+xml" />
    <title>AI Supply Chain Trust</title>
    <!--SSR_HEAD-->
    <script type="module" crossorigin src="/assets/js/app.js"></script>
  </head>
  <body>
    <div id="root"><!--SSR_MAIN--></div>
  </body>
</html>
"#;

    fn count(haystack: &str, needle: &str) -> usize {
        haystack.matches(needle).count()
    }

    #[test]
    fn routes_resolve_like_the_client_router() {
        assert_eq!(resolve_route("/", None), SpaRoute::Home);
        assert_eq!(resolve_route("/contexts", None), SpaRoute::Contexts);
        assert_eq!(resolve_route("/leaderboard/", None), SpaRoute::Leaderboard);
        assert_eq!(
            resolve_route("/about", None),
            SpaRoute::Legal(LegalPage::About)
        );
        assert_eq!(
            resolve_route("/result", Some("repo=ollama%2Follama")),
            SpaRoute::Result {
                repository: Some("ollama/ollama".to_string())
            }
        );
        assert_eq!(
            resolve_route("/r/ollama/ollama", None),
            SpaRoute::Repository {
                repository: "ollama/ollama".to_string()
            }
        );
        assert!(matches!(
            resolve_route("/r/ollama", None),
            SpaRoute::NotFound { .. }
        ));
        assert!(matches!(
            resolve_route("/nope", None),
            SpaRoute::NotFound { .. }
        ));
    }

    #[test]
    fn managed_tags_appear_exactly_once_per_page() {
        let document = render_document(SHELL, &SpaRoute::Home, "https://example.test", None);

        assert_eq!(count(&document, "<title"), 1);
        assert_eq!(count(&document, "name=\"description\""), 1);
        assert_eq!(count(&document, "rel=\"canonical\""), 1);
        for identity in [
            "og:title",
            "og:description",
            "og:url",
            "og:type",
            "og:site_name",
            "twitter:card",
            "twitter:title",
            "twitter:description",
        ] {
            assert_eq!(count(&document, identity), 1, "duplicate {identity}");
        }
        assert_eq!(count(&document, "application/ld+json"), 1);
        assert!(!document.contains("Agent-ready security context"));
        assert!(!document.contains("<title>AI Supply Chain Trust</title>"));
        assert!(!document.contains(HEAD_PLACEHOLDER));
        // Untouched shell tags survive.
        assert!(document.contains("<meta charset=\"UTF-8\" />"));
        assert!(document.contains("/assets/js/app.js"));
        assert!(document.contains("rel=\"icon\""));
    }

    /// `vite build` regenerates the shell, so the strip must not depend on
    /// exact formatting.
    #[test]
    fn reformatted_shell_tags_are_still_replaced() {
        let shell = r#"<!doctype html>
<html><head>
<META NAME='description' CONTENT='Agent-ready security context.'>
<TITLE  >AI Supply Chain Trust</TITLE>
<meta property=og:title content=stale>
<link href='https://example.test/stale' rel=canonical>
<script type='application/ld+json'>{"@type":"WebSite"}</script>
<!--SSR_HEAD-->
</head><body><div id="root"><!--SSR_MAIN--></div></body></html>"#;

        let document = render_document(shell, &SpaRoute::Contexts, "https://example.test", None);

        assert_eq!(count(&document.to_lowercase(), "<title"), 1);
        assert_eq!(count(&document.to_lowercase(), "og:title"), 1);
        assert_eq!(count(&document.to_lowercase(), "canonical"), 1);
        assert_eq!(count(&document, "application/ld+json"), 0);
        assert!(!document.contains("Agent-ready security context."));
        assert!(!document.contains("https://example.test/stale"));
        assert!(document.contains("<title>Public repository contexts | AI Supply Chain Trust"));
    }

    #[test]
    fn shell_without_placeholders_still_renders() {
        let shell = "<html><head><title>Old</title></head><body></body></html>";
        let document = render_document(shell, &SpaRoute::Leaderboard, "https://example.test", None);

        assert_eq!(count(&document, "<title"), 1);
        assert!(document.contains("Repository trust leaderboard"));
        assert!(document.contains("</head>"));

        // Nothing resembling a head at all: still a document, never a panic.
        let bare = render_document("plain text", &SpaRoute::Home, "https://example.test", None);
        assert!(bare.contains("plain text"));
        assert!(bare.contains("<title>"));
    }

    #[test]
    fn repository_route_publishes_the_stored_verdict() {
        let report = json!({
            "repo": "ollama/ollama",
            "grade": "B",
            "trust_score": 74.6,
            "verdict": "Review with known gaps",
            "action": "Review before adoption",
            "evaluated_at": "2026-07-11"
        });
        let route = resolve_route("/r/ollama/ollama", None);
        let document = render_document(
            SHELL,
            &route,
            "https://ai-supply-chain-trust.aibim.ai",
            Some(&report),
        );

        assert!(document.contains(
            "<title>ollama/ollama — trust grade B 75/100 | AI Supply Chain Trust</title>"
        ));
        assert!(document.contains("content=\"article\""));
        assert!(
            document.contains("href=\"https://ai-supply-chain-trust.aibim.ai/r/ollama/ollama\"")
        );
        assert!(document.contains("Review with known gaps (trust grade B 75/100)"));
        assert!(document.contains("\"@type\":\"SoftwareSourceCode\""));
        assert!(document.contains("\"ratingValue\":75"));
        assert_eq!(count(&document, "application/ld+json"), 1);
        // Crawlable stub.
        assert!(document.contains("<h1>ollama/ollama security context</h1>"));
        assert!(document.contains("Review with known gaps"));
        assert!(!document.contains(MAIN_PLACEHOLDER));
    }

    #[test]
    fn repository_without_a_report_degrades_to_generic_metadata() {
        let route = resolve_route("/r/unknown/repo", None);
        let document = render_document(SHELL, &route, "https://example.test", None);

        assert!(document
            .contains("<title>unknown/repo security context | AI Supply Chain Trust</title>"));
        assert!(document.contains(
            "Evidence-backed security context for the public GitHub repository unknown/repo"
        ));
        assert!(!document.contains("undefined"));
        assert!(!document.contains("NaN"));
        assert!(!document.contains("/100"));
        assert_eq!(count(&document, "application/ld+json"), 1);
    }

    #[test]
    fn only_the_not_found_route_carries_robots() {
        let not_found = render_document(
            SHELL,
            &resolve_route("/nope", None),
            "https://example.test",
            None,
        );
        assert_eq!(count(&not_found, "name=\"robots\""), 1);
        assert!(not_found.contains("content=\"noindex, follow\""));
        assert!(not_found.contains("href=\"https://example.test/nope\""));

        for path in [
            "/",
            "/contexts",
            "/leaderboard",
            "/result",
            "/about",
            "/editorial-policy",
            "/privacy",
            "/r/owner/name",
        ] {
            let document = render_document(
                SHELL,
                &resolve_route(path, None),
                "https://example.test",
                None,
            );
            assert_eq!(count(&document, "\"robots\""), 0, "robots leaked on {path}");
        }
    }

    #[test]
    fn result_route_is_the_only_canonical_with_a_query() {
        let route = resolve_route("/result", Some("repo=ollama%2Follama&tab=history"));
        let document = render_document(SHELL, &route, "https://example.test", None);
        assert!(document.contains("href=\"https://example.test/result?repo=ollama%2Follama\""));
        assert_eq!(count(&document, "rel=\"canonical\""), 1);
    }

    /// Repository slugs come from the URL path and are never trusted.
    #[test]
    fn hostile_repository_slugs_cannot_break_out_of_the_document() {
        for hostile in [
            "\"><script>alert(1)</script>",
            "owner/repo\" onload=\"alert(1)",
            "owner/</title><script>alert(1)</script>",
            "owner/repo'></script><script>alert(1)</script>",
            "owner/</script><img src=x onerror=alert(1)>",
        ] {
            let repository = if hostile.contains('/') {
                hostile.to_string()
            } else {
                format!("owner/{hostile}")
            };
            let route = SpaRoute::Repository {
                repository: repository.clone(),
            };
            let report = json!({
                "repo": repository,
                "grade": "A",
                "trust_score": 90.0,
                "verdict": "Safe</script><script>alert(2)</script>",
                "action": "Use\"><script>alert(3)</script>"
            });
            let document = render_document(SHELL, &route, "https://example.test", Some(&report));
            assert_no_injection(&document, 2);
            assert_eq!(count(&document, "application/ld+json"), 1);
            // The payload survives only as inert, escaped text.
            assert!(document.contains("&lt;") || document.contains("\\u003c"));
            // …and the JSON-LD block is still parseable JSON.
            let json_ld = extract_json_ld(&document).expect("json-ld block");
            serde_json::from_str::<Value>(&json_ld).expect("valid json-ld");
        }
    }

    #[test]
    fn hostile_result_query_is_escaped_too() {
        let route = resolve_route(
            "/result",
            Some("repo=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        );
        let document = render_document(SHELL, &route, "https://example.test", None);
        assert_no_injection(&document, 1);
        assert!(document.contains("&lt;script&gt;"));
    }

    /// The slug may only ever appear as escaped text: no new element, no new
    /// attribute, no closing tag.
    fn assert_no_injection(document: &str, expected_scripts: usize) {
        // JSON-LD is script *content*: quoting rules there are JSON's, and the
        // only escape that matters is `<`, which is asserted directly. The
        // block is then removed so the HTML assertions below only see markup.
        let mut document = document.to_string();
        if let Some(json_ld) = extract_json_ld(&document) {
            assert!(
                !json_ld.contains('<'),
                "raw '<' inside the JSON-LD block: {json_ld}"
            );
            if !json_ld.is_empty() {
                document = document.replace(&json_ld, "");
            }
        }
        let document = document.as_str();
        assert_eq!(
            count(document, "<script"),
            expected_scripts,
            "unexpected script element: {document}"
        );
        assert_eq!(count(document, "</script>"), expected_scripts);
        assert_eq!(count(document, "<title"), 1);
        assert_eq!(count(document, "</title>"), 1);
        assert!(!document.contains("<img"), "{document}");
        assert!(!document.contains("<svg"));
        for marker in [
            "\"><script",
            "'><script",
            "</title><",
            "</script><script",
            "\" onload",
            "\" onerror",
            "' onload",
            "' onerror",
        ] {
            assert!(
                !document.contains(marker),
                "attribute breakout via {marker}: {document}"
            );
        }
    }

    fn extract_json_ld(document: &str) -> Option<String> {
        let marker = "data-seo=\"route\">";
        let start = document.find(marker)? + marker.len();
        let end = document[start..].find("</script>")? + start;
        Some(document[start..end].to_string())
    }

    #[test]
    fn home_json_ld_is_a_two_node_array_with_stable_ids() {
        let document = render_document(SHELL, &SpaRoute::Home, "https://example.test", None);
        let start = document.find("data-seo=\"route\">").unwrap() + "data-seo=\"route\">".len();
        let end = document[start..].find("</script>").unwrap() + start;
        let parsed: Value = serde_json::from_str(&document[start..end]).unwrap();
        let nodes = parsed.as_array().expect("two-element array");

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["@id"], json!("https://example.test/#website"));
        assert_eq!(nodes[1]["@id"], json!("https://example.test/#organization"));
        assert_eq!(nodes[0]["@type"], json!("WebSite"));
        assert_eq!(nodes[1]["@type"], json!("Organization"));
    }
}
