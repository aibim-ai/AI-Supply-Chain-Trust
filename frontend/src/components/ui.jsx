import { LoaderCircle } from "lucide-react";

export function Spinner() {
  return <LoaderCircle className="spin" size={20} aria-label="Loading" />;
}
export function GradeBadge({ grade }) {
  const value = String(grade || "").toUpperCase();
  const color = value.startsWith("A")
    ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:bg-emerald-950"
    : value.startsWith("B")
      ? "border-blue-200 bg-blue-50 text-blue-700 dark:bg-blue-950"
      : value.startsWith("C")
        ? "border-amber-200 bg-amber-50 text-amber-700 dark:bg-amber-950"
        : "border-rose-200 bg-rose-50 text-rose-700 dark:bg-rose-950";
  return <span className={`pill ${color}`}>{grade || "—"}</span>;
}
export function ErrorState({ error, retry }) {
  return (
    <div className="panel narrow">
      <h2>We couldn't load this view</h2>
      <p>{error?.message || String(error)}</p>
      {retry && (
        <button className="button button-secondary" onClick={retry}>
          Try again
        </button>
      )}
    </div>
  );
}
export function PageHeader({ eyebrow, title, description, action }) {
  return (
    <header className="page-title">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </header>
  );
}
export function PageLoader() {
  return (
    <div className="page-loader narrow" aria-label="Loading page">
      <div className="page-loader-mark">
        <span />
      </div>
      <div className="page-loader-lines">
        <i />
        <i />
        <i />
      </div>
    </div>
  );
}
