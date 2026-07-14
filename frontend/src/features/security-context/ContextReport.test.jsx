import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ContextReport } from "./ContextReport";

const payload = {
  generated_at: "2026-07-10T12:00:00Z",
  summary: {
    fixes: 2,
    cves: 1,
    top_severity: "high",
  },
  artifacts: {
    security_context_json: "/r/example/repo.json",
    security_context_md: "/r/example/repo.md",
    vulnerability_leads_json: "/r/example/repo.leads.json",
    vulnerability_leads_md: "/r/example/repo.leads.md",
  },
  context: {
    revision: "abcdef1234567890",
    commits_scanned: 120,
    remediation: { coverage: 50 },
    vuln_class_counts: {
      "Input validation": 2,
    },
    component_counts: {
      parser: 2,
    },
    top_risks: [
      {
        vuln_class: "Input validation",
        rationale: "Parser boundary checks have regressed before.",
      },
    ],
    watchlist: [
      {
        id: "rc_input_validation_parser",
        schema_version: "1.0",
        title: "Preserve Input validation protection in parser",
        invariant:
          "Changes to parser must preserve the cited historical security boundary.",
        vulnerability_class: "Input validation",
        impact: "high",
        evidence_tier: "e3",
        source_evidence: [
          {
            relation: "fixed_by",
            id: "commit:abcdef1234567890",
            summary: "Fix bounds check in parser",
          },
        ],
        surfaces: [
          {
            path: "src/parser.rs",
            component: "parser",
            symbols: ["parse_packet"],
            sinks: ["parse_packet length handling"],
          },
        ],
        guards: [],
        lifecycle: { state: "active" },
        owner: { codeowners: ["@appsec"], source: "CODEOWNERS" },
        assessment: {
          state: "analysis_unavailable",
          disposition: "unknown",
          guard_status: "not_found",
          explanation: "No base/head diff or guard execution was supplied.",
          missing_analysis: ["base_head_diff", "guard_execution"],
          check_conclusion: "action_required",
        },
      },
    ],
    fingerprints: [
      {
        commit_sha: "abcdef1234567890",
        commit_date: "2026-07-01",
        severity: "high",
        vuln_class: "Input validation",
        summary: "Fix bounds check in parser",
        sink: "parse_packet length handling",
        fix_shape: "reject oversized length",
        components: ["parser"],
      },
      {
        commit_sha: "1234567890abcdef",
        commit_date: "2026-07-02",
        severity: "medium",
        vuln_class: "Input validation",
        summary: "Validate nested field count",
        sink: "nested field count",
        fix_shape: "cap nested fields",
        components: ["parser"],
      },
    ],
    known_cves: [
      {
        id: "CVE-2026-0001",
        severity: "high",
        cvss: 8.1,
        summary: "Input validation issue in parser.",
      },
    ],
  },
};

describe("ContextReport", () => {
  it("renders a ready security context report with legacy sections", () => {
    const html = renderToStaticMarkup(
      <ContextReport repository="example/repo" payload={payload} />,
    );

    expect(html).toContain("securitycontext-page");
    expect(html).toContain("Regression watchlist");
    expect(html).toContain("Distribution");
    expect(html).toContain("Fixed vulnerabilities");
    expect(html).toContain("Disclosed CVEs");
    expect(html).toContain("security context json");
    expect(html).toContain("vulnerability leads md");
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain("Input validation");
    expect(html).toContain("CVE-2026-0001");
    expect(html).toContain("E3 · active");
    expect(html).toContain("No guard found");
    expect(html).toContain("Analysis unavailable");
    expect(html).toContain("missing: base head diff");
    expect(html).toContain("owner: @appsec");
    expect(html).toContain("check: action_required");
    expect(html).toContain('data-label="Protected surface"');
    expect(html).toContain('data-label="Vulnerability"');
    expect(html).not.toContain("Guard parser");
  });

  it("collapses long regression watchlists after the first eight contracts", () => {
    const contracts = Array.from({ length: 10 }, (_, index) => ({
      ...payload.context.watchlist[0],
      id: `contract-${index}`,
      title: `Regression contract ${index + 1}`,
    }));
    const html = renderToStaticMarkup(
      <ContextReport
        repository="example/repo"
        payload={{
          ...payload,
          context: { ...payload.context, watchlist: contracts },
        }}
      />,
    );

    expect(html).toContain("Show all regression contracts");
    expect(html).toContain("(2 more)");
    expect(html).toContain("sc-watch-continuation");
  });
});
