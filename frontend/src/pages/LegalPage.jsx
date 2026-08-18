import { useDocumentMeta } from "../hooks/use-document-meta";
import { pageTitle } from "../lib/seo";

const content = {
  about: [
    "About",
    "AI Supply Chain Trust turns public repository evidence into reusable review context for humans and coding agents.",
  ],
  policy: [
    "Editorial policy",
    "Reports distinguish observed evidence, derived signals, and unavailable data. They do not invent missing evidence or claim exhaustive security review.",
  ],
  privacy: [
    "Privacy",
    "Only public repository inputs are supported. Scan results and generated context are public and may be cached. Optional Google Analytics and PostHog collection starts only after consent and may use browser storage or cookies. Analytics events exclude repository names, search text, findings, artifact URLs, and feedback messages; session recordings mask inputs and page text. You can change your choice from the footer.",
  ],
};

const meta = {
  about: [
    "/about",
    "How AI Supply Chain Trust turns public repository evidence into reusable, traceable review context for people and coding agents.",
  ],
  policy: [
    "/editorial-policy",
    "How reports separate observed evidence, derived signals, and unavailable data — and what they deliberately do not claim.",
  ],
  privacy: [
    "/privacy",
    "What AI Supply Chain Trust collects: public repository inputs only, public cacheable results, and analytics that start only after consent.",
  ],
};

export default function LegalPage({ type }) {
  const [title, text] = content[type];
  const [path, description] = meta[type];
  useDocumentMeta({ title: pageTitle(title), description, path });
  return (
    <section className="shell py-20">
      <article className="card mx-auto max-w-3xl p-8 sm:p-12">
        <span className="label">AI Supply Chain Trust</span>
        <h1 className="mt-3 text-4xl font-semibold">{title}</h1>
        <p className="mt-6 text-lg leading-8 text-slate-500">{text}</p>
      </article>
    </section>
  );
}
