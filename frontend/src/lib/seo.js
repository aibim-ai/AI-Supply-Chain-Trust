// Per-route document metadata.
//
// The served HTML shell can be pre-rendered with the very same tags (the
// `<!--SSR_HEAD-->` placeholder in index.html). Every writer below therefore
// resolves a tag by its identity first and mutates it in place; a tag is only
// created when the document does not carry one yet, and any accidental
// duplicate of the same identity is dropped. Navigating between routes must
// never grow the <head>.
//
// Tag identities managed here:
//   <title>
//   link[rel="canonical"]
//   meta[name="description"]
//   meta[name="robots"]                      (optional, removed when unset)
//   meta[property="og:title" | "og:description" | "og:url" | "og:type" | "og:site_name"]
//   meta[name="twitter:card" | "twitter:title" | "twitter:description"]
//   script[type="application/ld+json"][data-seo="route"]  (optional, removed when unset)

export const SITE_NAME = "AI Supply Chain Trust";
export const PRODUCTION_ORIGIN = "https://ai-supply-chain-trust.aibim.ai";

const MANAGED_ATTRIBUTE = "data-seo-managed";
const JSON_LD_SELECTOR = 'script[type="application/ld+json"]';

export function siteOrigin() {
  const origin = globalThis.window?.location?.origin;
  return typeof origin === "string" && /^https?:\/\//i.test(origin)
    ? origin.replace(/\/+$/, "")
    : PRODUCTION_ORIGIN;
}

export function absoluteUrl(path = "/") {
  const origin = siteOrigin();
  const suffix = String(path || "/");
  const candidate = /^https?:\/\//i.test(suffix)
    ? suffix
    : `${origin}${suffix.startsWith("/") ? "" : "/"}${suffix}`;
  return safeUrl(candidate, origin);
}

// Canonical and og:url end up in an href attribute, and their path segments come
// from route params (`/r/:owner/:repository`). Resolve through the URL parser and
// allow only http(s), so no other scheme can ever reach the attribute regardless
// of what a caller passes in.
export function safeUrl(value, origin = siteOrigin()) {
  const fallback = `${origin}/`;
  try {
    const parsed = new globalThis.URL(String(value ?? ""), fallback);
    return parsed.protocol === "https:" || parsed.protocol === "http:"
      ? parsed.href
      : fallback;
  } catch {
    return fallback;
  }
}

export function pageTitle(text) {
  const value = String(text || "").trim();
  if (!value) return SITE_NAME;
  return value === SITE_NAME ? value : `${value} | ${SITE_NAME}`;
}

export function applyDocumentMeta(meta = {}) {
  const head = globalThis.document?.head;
  if (!head) return;

  const title = meta.title || SITE_NAME;
  const description = meta.description || "";
  // Sanitized here as well as in `absoluteUrl`, so a caller-supplied `meta.url`
  // reaches the href attribute through the same scheme allow-list.
  const url = safeUrl(meta.url || absoluteUrl(meta.path || "/"));

  if (globalThis.document.title !== title) globalThis.document.title = title;

  upsert(
    head,
    'link[rel="canonical"]',
    url,
    () => createElement("link", { rel: "canonical" }),
    (element, value) => element.setAttribute("href", value),
  );
  setMetaName(head, "description", description);
  setMetaName(head, "robots", meta.robots);
  setMetaProperty(head, "og:title", meta.socialTitle || title);
  setMetaProperty(head, "og:description", description);
  setMetaProperty(head, "og:url", url);
  setMetaProperty(head, "og:type", meta.type || "website");
  setMetaProperty(head, "og:site_name", SITE_NAME);
  setMetaName(head, "twitter:card", meta.twitterCard || "summary");
  setMetaName(head, "twitter:title", meta.socialTitle || title);
  setMetaName(head, "twitter:description", description);
  setJsonLd(head, meta.jsonLd);
}

function setMetaName(head, name, content) {
  upsert(
    head,
    `meta[name="${name}"]`,
    content,
    () => createElement("meta", { name }),
    (element, value) => element.setAttribute("content", value),
  );
}

function setMetaProperty(head, property, content) {
  upsert(
    head,
    `meta[property="${property}"]`,
    content,
    () => createElement("meta", { property }),
    (element, value) => element.setAttribute("content", value),
  );
}

function setJsonLd(head, jsonLd) {
  const nodes = (Array.isArray(jsonLd) ? jsonLd : [jsonLd]).filter(Boolean);
  const serialized = nodes.length
    ? JSON.stringify(nodes.length === 1 ? nodes[0] : nodes)
    : "";
  upsert(
    head,
    JSON_LD_SELECTOR,
    serialized,
    () =>
      createElement("script", {
        type: "application/ld+json",
        "data-seo": "route",
      }),
    (element, value) => {
      element.setAttribute("data-seo", "route");
      if (element.textContent !== value) element.textContent = value;
    },
  );
}

// Resolves a tag by identity: reuse the first match (server-injected or
// client-created), drop duplicates, create only when nothing matches, and
// remove the tag entirely when the route supplies no value for it.
function upsert(head, selector, value, create, apply) {
  const existing = Array.from(head.querySelectorAll(selector));
  if (!value) {
    existing.forEach((element) => element.remove());
    return;
  }
  const [first, ...duplicates] = existing;
  duplicates.forEach((element) => element.remove());
  const element = first || head.appendChild(create());
  element.setAttribute(MANAGED_ATTRIBUTE, "true");
  apply(element, value);
}

function createElement(tag, attributes) {
  const element = globalThis.document.createElement(tag);
  Object.entries(attributes).forEach(([key, value]) =>
    element.setAttribute(key, value),
  );
  return element;
}

export function websiteJsonLd({ description }) {
  const origin = siteOrigin();
  return [
    {
      "@context": "https://schema.org",
      "@type": "WebSite",
      "@id": `${origin}/#website`,
      name: SITE_NAME,
      url: `${origin}/`,
      description,
      publisher: { "@id": `${origin}/#organization` },
    },
    {
      "@context": "https://schema.org",
      "@type": "Organization",
      "@id": `${origin}/#organization`,
      name: "AIBIM",
      url: `${origin}/`,
      logo: `${origin}/aibim-logo.svg`,
      brand: SITE_NAME,
    },
  ];
}

// Describes the evaluated repository and, when the evaluation is loaded, the
// published trust verdict. Only values present in the payload are emitted.
export function repositoryJsonLd({
  repository,
  url,
  description,
  score,
  grade,
  verdict,
  action,
  evaluatedAt,
}) {
  const node = {
    "@context": "https://schema.org",
    "@type": "SoftwareSourceCode",
    name: repository,
    codeRepository: `https://github.com/${repository}`,
    url,
  };
  if (description) node.description = description;

  const rating = {};
  if (Number.isFinite(score)) {
    rating["@type"] = "Rating";
    rating.ratingValue = Math.round(score);
    rating.bestRating = 100;
    rating.worstRating = 0;
  }
  if (grade) {
    rating["@type"] = "Rating";
    rating.alternateName = grade;
  }

  const reviewBody = [verdict, action].filter(Boolean).join(" — ");
  if (Object.keys(rating).length || reviewBody) {
    node.subjectOf = {
      "@type": "Review",
      name: `${repository} trust verdict`,
      url,
      author: {
        "@type": "Organization",
        name: SITE_NAME,
        url: `${siteOrigin()}/`,
      },
    };
    if (reviewBody) node.subjectOf.reviewBody = reviewBody;
    if (evaluatedAt) node.subjectOf.datePublished = evaluatedAt;
    if (Object.keys(rating).length) node.subjectOf.reviewRating = rating;
  }
  return node;
}
