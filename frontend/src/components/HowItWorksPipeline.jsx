import { useEffect, useState } from "react";
import {
  Check,
  CirclePause,
  CirclePlay,
  Database,
  FileJson,
  GitBranch,
  Layers3,
  Radio,
  ScanSearch,
  ShieldCheck,
} from "lucide-react";

const REPLAY_INTERVAL = 2800;

const stages = [
  {
    name: "Capture",
    phase: "Queued → running",
    icon: GitBranch,
    title: "Lock the repository snapshot",
    description:
      "Normalize the public repository, persist the job, and bind the scan to the observed default branch and HEAD.",
    source: "Public repository",
    processor: "Snapshot identity",
    outcome: "Stable scan input",
    events: [
      ["Input", "Repository normalized"],
      ["State", "Durable job accepted"],
      ["Anchor", "Branch + HEAD observed"],
    ],
  },
  {
    name: "Evaluate",
    phase: "Foreground",
    icon: ScanSearch,
    title: "Publish the fast evidence state",
    description:
      "Run the deterministic first pass quickly. Coverage and missing sources stay explicit while deeper evidence continues.",
    source: "Metadata + policy",
    processor: "Deterministic rules",
    outcome: "Fast result ready",
    events: [
      ["Signal", "Repository metadata evaluated"],
      ["Boundary", "Missing evidence retained"],
      ["Event", "fast_ready published"],
    ],
  },
  {
    name: "Enrich",
    phase: "Parallel workers",
    icon: Layers3,
    title: "Correlate history and advisories",
    description:
      "Checkpoint commit history, inspect bounded commit details, and correlate GitHub advisories, OSV, and NVD evidence in parallel.",
    source: "History + advisories",
    processor: "Evidence graph",
    outcome: "Ranked review leads",
    events: [
      ["History", "Commit pages checkpointed"],
      ["Intel", "OSV / NVD correlated"],
      ["Fixes", "Security changes classified"],
    ],
  },
  {
    name: "Publish",
    phase: "Evidence gated",
    icon: ShieldCheck,
    title: "Release reusable trusted context",
    description:
      "Only grounded claims pass the evidence gate. The completed context becomes available to people, APIs, and coding agents.",
    source: "Verified evidence",
    processor: "Fact + evidence gate",
    outcome: "Context ready",
    events: [
      ["Guardrail", "Claims tied to sources"],
      ["Artifacts", "JSON + Markdown generated"],
      ["Delivery", "Web + REST + MCP ready"],
    ],
  },
];

export default function HowItWorksPipeline() {
  const [activeStage, setActiveStage] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [motionAllowed, setMotionAllowed] = useState(true);
  const stage = stages[activeStage];
  const StageIcon = stage.icon;

  useEffect(() => {
    const media = globalThis.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!media) return undefined;
    const syncMotionPreference = () => {
      const allowed = !media.matches;
      setMotionAllowed(allowed);
      if (!allowed) setPlaying(false);
    };
    syncMotionPreference();
    media.addEventListener?.("change", syncMotionPreference);
    return () => media.removeEventListener?.("change", syncMotionPreference);
  }, []);

  useEffect(() => {
    if (!playing || !motionAllowed) return undefined;
    const timer = globalThis.setInterval(
      () => setActiveStage((current) => (current + 1) % stages.length),
      REPLAY_INTERVAL,
    );
    return () => globalThis.clearInterval(timer);
  }, [playing, motionAllowed]);

  function chooseStage(index) {
    setActiveStage(index);
    setPlaying(false);
  }

  return (
    <section className="how-it-works" aria-labelledby="how-it-works-title">
      <div className="how-it-works-heading">
        <div>
          <span className="eyebrow">A scan, replayed</span>
          <h2 id="how-it-works-title">From repository to trusted context.</h2>
        </div>
        <p>
          A fast result appears first. Durable enrichment keeps moving until
          every required evidence source reaches a terminal state.
        </p>
      </div>

      <div className="pipeline-replay">
        <div className="pipeline-replay-toolbar">
          <span className="pipeline-live-label">
            <Radio size={14} aria-hidden="true" /> Realtime pipeline replay
          </span>
          <span className="pipeline-stage-count">
            Stage {String(activeStage + 1).padStart(2, "0")} / 04
          </span>
          <button
            type="button"
            className="pipeline-playback"
            onClick={() => setPlaying((current) => !current)}
            aria-label={
              playing ? "Pause pipeline replay" : "Play pipeline replay"
            }
            disabled={!motionAllowed}
          >
            {playing ? (
              <CirclePause size={17} aria-hidden="true" />
            ) : (
              <CirclePlay size={17} aria-hidden="true" />
            )}
            <span>{playing ? "Pause" : "Play"}</span>
          </button>
        </div>

        <div
          className="pipeline-progress"
          style={{ "--pipeline-progress": `${((activeStage + 1) / 4) * 100}%` }}
          aria-hidden="true"
        >
          <i />
        </div>

        <ol className="pipeline-stepper" aria-label="Trust pipeline stages">
          {stages.map((item, index) => {
            const Icon = item.icon;
            const state =
              index === activeStage
                ? "active"
                : index < activeStage
                  ? "complete"
                  : "waiting";
            return (
              <li className="pipeline-step-item" key={item.name}>
                <button
                  type="button"
                  className="pipeline-step"
                  data-state={state}
                  aria-current={index === activeStage ? "step" : undefined}
                  onClick={() => chooseStage(index)}
                >
                  <span className="pipeline-step-index">
                    {index < activeStage ? (
                      <Check size={14} aria-hidden="true" />
                    ) : (
                      `0${index + 1}`
                    )}
                  </span>
                  <span className="pipeline-step-copy">
                    <strong>{item.name}</strong>
                    <small>{item.phase}</small>
                  </span>
                  <Icon size={16} aria-hidden="true" />
                </button>
              </li>
            );
          })}
        </ol>

        <div className="pipeline-runtime" key={stage.name}>
          <div className="pipeline-runtime-copy">
            <span className="pipeline-runtime-kicker">
              <i aria-hidden="true" /> Now processing
            </span>
            <h3>{stage.title}</h3>
            <p>{stage.description}</p>
          </div>

          <div className="pipeline-route" aria-hidden="true">
            <div className="pipeline-route-node pipeline-route-source">
              <Database size={17} />
              <span>{stage.source}</span>
            </div>
            <div className="pipeline-route-rail">
              <i />
              <i />
              <i />
            </div>
            <div className="pipeline-route-core">
              <span className="pipeline-core-orbit" />
              <StageIcon size={25} />
              <strong>{stage.processor}</strong>
            </div>
            <div className="pipeline-route-rail" data-direction="out">
              <i />
              <i />
              <i />
            </div>
            <div className="pipeline-route-node pipeline-route-output">
              <FileJson size={17} />
              <span>{stage.outcome}</span>
            </div>
          </div>

          <div
            className="pipeline-event-log"
            role="list"
            aria-label={`${stage.name} activity`}
          >
            {stage.events.map(([label, message], index) => (
              <div
                role="listitem"
                style={{ "--event-index": index }}
                key={label}
              >
                <span>{label}</span>
                <strong>{message}</strong>
                <i aria-hidden="true" />
              </div>
            ))}
          </div>
        </div>

        <div
          className="pipeline-delivery"
          aria-label="Published context formats"
        >
          <span>Delivered as</span>
          <strong>Web</strong>
          <strong>JSON</strong>
          <strong>Markdown</strong>
          <strong>REST</strong>
          <strong>MCP</strong>
        </div>
      </div>
    </section>
  );
}
