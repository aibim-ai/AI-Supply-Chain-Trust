import { useEffect } from "react";
import { useLocation } from "react-router-dom";

export function ScanProgress({ repository, retry }) {
  const location = useLocation();
  const params = new globalThis.URLSearchParams(location.search);
  const scanStatus = params.get("scan") || "running";
  const isFailed = scanStatus === "failed";
  const isActive = scanStatus === "queued" || scanStatus === "running";

  useEffect(() => {
    const activePath = `${location.pathname}${location.search}`;
    const refreshIfActive = () => {
      const current = `${globalThis.location.pathname}${globalThis.location.search}`;
      if (current === activePath) retry();
    };
    let events;
    if ("EventSource" in globalThis) {
      events = new globalThis.EventSource("/api/v1/events");
      events.onmessage = refreshIfActive;
    }
    return () => {
      events?.close();
    };
  }, [location.pathname, location.search, retry]);

  const steps = isFailed
    ? [
        [
          "Failed",
          "Scan stopped before a context could be published",
          "failed",
        ],
        [
          "Evidence fetch",
          "GitHub metadata, commit history, advisories, and CVEs",
          undefined,
        ],
        [
          "Building context",
          "Security fingerprints, CVE list, and leads",
          undefined,
        ],
        ["Publishing result", "Results appear here automatically", undefined],
      ]
    : [
        ["Queued", "Job accepted", scanStatus === "queued" ? "active" : "done"],
        [
          "Fetching evidence",
          "GitHub metadata, commit history, advisories, and CVEs",
          scanStatus === "running" ? "active" : undefined,
        ],
        [
          "Building context",
          "Security fingerprints, CVE list, and leads",
          undefined,
        ],
        ["Publishing result", "Results appear here automatically", undefined],
      ];

  return (
    <section className="page-stack narrow">
      <section className="panel scan-progress-panel" aria-busy={isActive}>
        <span className="eyebrow">
          {isFailed ? "Scan failed" : "Scan in progress"}
        </span>
        <h1>{repository}</h1>
        <p>
          {isFailed
            ? "The scan did not complete. Queue it again after the upstream dependency recovers."
            : scanStatus === "queued"
              ? "The scan is queued. This public page updates automatically when repository evidence becomes available."
              : "Repository evidence is being collected. A fast result will appear before historical enrichment completes."}
        </p>
        <div className="scan-progress-list">
          {steps.map(([title, detail, state]) => (
            <article data-state={state} key={title}>
              <span />
              <strong>{title}</strong>
              <em>{detail}</em>
            </article>
          ))}
        </div>
        {!isFailed && (
          <p className="scan-progress-note">
            You can leave this page and return to the same public URL later.
          </p>
        )}
      </section>
    </section>
  );
}
