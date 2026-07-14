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
    "Only public repository inputs are supported. Scan results and generated context are public and may be cached.",
  ],
};
export default function LegalPage({ type }) {
  const [title, text] = content[type];
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
