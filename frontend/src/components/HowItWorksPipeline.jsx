import {
  Code2,
  FileDiff,
  GitBranch,
  GitCommitHorizontal,
  LockKeyhole,
  Network,
  ShieldCheck,
  Sparkles,
  Tag,
  Target,
} from "lucide-react";

const sources = [
  { label: "Diffs", icon: FileDiff, x: 11.5, y: 24 },
  { label: "Source code", icon: Code2, x: 31, y: 8.5 },
  { label: "Security fixes", icon: ShieldCheck, x: 26, y: 32 },
  { label: "Commit history", icon: GitCommitHorizontal, x: 50, y: 5 },
  { label: "CVE / GHSA", icon: LockKeyhole, x: 73, y: 9 },
  { label: "Branches", icon: GitBranch, x: 77, y: 32 },
  { label: "Releases", icon: Tag, x: 91, y: 24 },
];

const outputs = [
  { label: "SECURITY_CONTEXT.md", icon: LockKeyhole, x: 30, y: 80 },
  { label: "VARIANT_LEADS.md", icon: Target, x: 70, y: 80 },
  {
    label: "Agent context",
    icon: Sparkles,
    x: 50,
    y: 94,
    center: true,
  },
];

const paths = [
  "M138 197 V270 H450 V310",
  "M372 86 V255 H500 V310",
  "M312 254 V280 H550 V310",
  "M600 60 V310",
  "M876 90 V255 H650 V310",
  "M924 254 V280 H700 V310",
  "M1092 197 V270 H750 V310",
  "M500 428 V520 H360 V552",
  "M600 428 V652",
  "M700 428 V520 H840 V552",
];

function PipelineNode({ node, kind }) {
  const Icon = node.icon;
  return (
    <article
      className={`pipeline-node pipeline-${kind}`}
      data-center={node.center ? "true" : undefined}
      role="listitem"
      style={{ "--node-x": `${node.x}%`, "--node-y": `${node.y}%` }}
    >
      <Icon size={16} aria-hidden="true" />
      <span>{node.label}</span>
    </article>
  );
}

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

      <div className="pipeline-network" role="list" aria-label="Trust pipeline">
        <svg
          className="pipeline-connections"
          viewBox="0 0 1200 720"
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          <g className="pipeline-base-paths">
            {paths.map((path) => (
              <path d={path} pathLength="100" key={`base-${path}`} />
            ))}
          </g>
          <g className="pipeline-flow-paths">
            {paths.map((path, index) => (
              <path
                d={path}
                pathLength="100"
                style={{ "--path-delay": `${index * -0.42}s` }}
                key={`flow-${path}`}
              />
            ))}
          </g>
        </svg>

        {sources.map((source) => (
          <PipelineNode node={source} kind="source" key={source.label} />
        ))}

        <article className="pipeline-center" role="listitem">
          <span className="pipeline-center-icon" aria-hidden="true">
            <Network size={18} />
          </span>
          <div>
            <strong>Consolidated security data</strong>
            <p>
              Every source becomes one structured evidence set, tied to what
              this repository has already fixed.
            </p>
          </div>
        </article>

        {outputs.map((output) => (
          <PipelineNode node={output} kind="output" key={output.label} />
        ))}
      </div>
    </section>
  );
}
