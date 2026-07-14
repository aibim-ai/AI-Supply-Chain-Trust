import {
  Bot,
  Braces,
  Database,
  FileCheck2,
  GitBranch,
  ShieldCheck,
} from "lucide-react";

const steps = [
  {
    number: "01",
    icon: GitBranch,
    title: "Select a repository",
    description: "Start with a public GitHub repository and its live metadata.",
    meta: "owner/repo",
  },
  {
    number: "02",
    icon: Database,
    title: "Collect evidence",
    description:
      "GitHub history, advisories, OSV, and NVD arrive as traceable evidence.",
    meta: "GitHub · OSV · NVD",
  },
  {
    number: "03",
    icon: ShieldCheck,
    title: "Apply trust rules",
    description:
      "Deterministic pillars score available signals and expose every gap.",
    meta: "score · grade · coverage",
  },
  {
    number: "04",
    icon: Bot,
    title: "Bounded LLM assist",
    description:
      "When configured, Gemma can classify supplied evidence—never invent it.",
    meta: "optional · OpenRouter",
    optional: true,
  },
  {
    number: "05",
    icon: FileCheck2,
    title: "Verify every claim",
    description:
      "Schema and fact checks accept grounded output or fall back to rules.",
    meta: "accept · reject · fallback",
  },
  {
    number: "06",
    icon: Braces,
    title: "Reuse the context",
    description:
      "Ship the same security context to people, pipelines, and coding agents.",
    meta: "Web · JSON · MD · MCP",
  },
];

export default function HowItWorksPipeline() {
  return (
    <section className="how-it-works" aria-labelledby="how-it-works-title">
      <div className="how-it-works-heading">
        <div>
          <span className="eyebrow">How it works</span>
          <h2 id="how-it-works-title">
            Evidence moves. Trust stays explainable.
          </h2>
        </div>
        <p>
          A progressive pipeline turns repository signals into a reusable
          security context without treating missing data as proof of safety.
        </p>
      </div>

      <div className="trust-pipeline" role="list" aria-label="Trust pipeline">
        {steps.map((step, index) => {
          const Icon = step.icon;
          return (
            <div className="pipeline-segment" key={step.number}>
              <article
                className="pipeline-step"
                data-optional={step.optional ? "true" : undefined}
                role="listitem"
              >
                <div className="pipeline-step-top">
                  <span className="pipeline-step-number">{step.number}</span>
                  <span className="pipeline-step-icon" aria-hidden="true">
                    <Icon size={18} />
                  </span>
                </div>
                <h3>{step.title}</h3>
                <p>{step.description}</p>
                <span className="pipeline-step-meta">{step.meta}</span>
              </article>
              {index < steps.length - 1 && (
                <span
                  className="pipeline-connector"
                  style={{ "--pipeline-delay": `${index * 0.48}s` }}
                  aria-hidden="true"
                />
              )}
            </div>
          );
        })}
      </div>

      <div className="llm-proof-rail" aria-label="Bounded LLM decision path">
        <span className="llm-proof-label">LLM safety path</span>
        <code>rule result</code>
        <i aria-hidden="true">→</i>
        <code>Gemma when available</code>
        <i aria-hidden="true">→</i>
        <code>schema + evidence check</code>
        <i aria-hidden="true">→</i>
        <code>accept or rule fallback</code>
      </div>
    </section>
  );
}
