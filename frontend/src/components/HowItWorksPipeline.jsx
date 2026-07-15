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
    title: "Choose a repo",
    detail: "Public repository",
  },
  {
    number: "02",
    icon: Database,
    title: "Gather evidence",
    detail: "GitHub · OSV · NVD",
  },
  {
    number: "03",
    icon: ShieldCheck,
    title: "Score signals",
    detail: "Rules · coverage",
  },
  {
    number: "04",
    icon: Bot,
    title: "Bounded LLM assist",
    detail: "Evidence only",
    optional: true,
  },
  {
    number: "05",
    icon: FileCheck2,
    title: "Verify claims",
    detail: "Schema · facts",
  },
  {
    number: "06",
    icon: Braces,
    title: "Reuse context",
    detail: "Web · JSON · MCP",
  },
];

export default function HowItWorksPipeline() {
  return (
    <section className="how-it-works" aria-labelledby="how-it-works-title">
      <div className="how-it-works-heading">
        <div>
          <span className="eyebrow">How it works</span>
          <h2 id="how-it-works-title">From repository to trusted context.</h2>
        </div>
        <p>One traceable workflow. Every claim stays tied to evidence.</p>
      </div>

      <div className="trust-pipeline" role="list" aria-label="Trust pipeline">
        <span className="pipeline-track" aria-hidden="true" />
        <span className="pipeline-signal" aria-hidden="true">
          <i />
        </span>

        {steps.map((step, index) => {
          const Icon = step.icon;
          return (
            <article
              className="pipeline-step"
              data-optional={step.optional ? "true" : undefined}
              role="listitem"
              style={{ "--step-index": index }}
              key={step.number}
            >
              <div className="pipeline-step-top">
                <span className="pipeline-step-number">{step.number}</span>
                {step.optional && (
                  <span className="pipeline-optional">Optional</span>
                )}
              </div>
              <span className="pipeline-step-icon" aria-hidden="true">
                <Icon size={17} />
              </span>
              <h3>{step.title}</h3>
              <span className="pipeline-step-detail">{step.detail}</span>
            </article>
          );
        })}
      </div>
    </section>
  );
}
