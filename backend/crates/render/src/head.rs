use super::esc;

pub fn build_head(
    title: &str,
    description: &str,
    path: &str,
    base_url: &str,
    indexable: bool,
    json_ld: &str,
) -> String {
    let canonical = format!("{base_url}{path}");
    let robots = if indexable {
        "index,follow,max-snippet:-1,max-image-preview:large"
    } else {
        "noindex,follow"
    };
    format!(
        "<title>{}</title>\n  \
         <meta name=\"description\" content=\"{}\">\n  \
         <meta name=\"robots\" content=\"{}\">\n  \
         <link rel=\"canonical\" href=\"{}\">\n  \
         <meta property=\"og:title\" content=\"{}\">\n  \
         <meta property=\"og:description\" content=\"{}\">\n  \
         <meta property=\"og:url\" content=\"{}\">\n  \
         <meta name=\"twitter:card\" content=\"summary_large_image\">\n  \
         <meta name=\"twitter:title\" content=\"{}\">\n  \
         <meta name=\"twitter:description\" content=\"{}\">\n  \
         {}",
        esc(title),
        esc(description),
        robots,
        esc(&canonical),
        esc(title),
        esc(description),
        esc(&canonical),
        esc(title),
        esc(description),
        json_ld
    )
}
