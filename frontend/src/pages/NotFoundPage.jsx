import { Link } from "react-router-dom";
import { useDocumentMeta } from "../hooks/use-document-meta";
import { pageTitle } from "../lib/seo";

export default function NotFoundPage() {
  useDocumentMeta({
    title: pageTitle("Page not found"),
    description:
      "This page does not exist. Browse published repository security contexts or scan a public GitHub repository.",
    path:
      globalThis.window?.location?.pathname &&
      globalThis.window.location.pathname !== "/"
        ? globalThis.window.location.pathname
        : "/",
    robots: "noindex, follow",
  });
  return (
    <section className="shell py-24 text-center">
      <span className="label">404</span>
      <h1 className="mt-3 text-4xl font-semibold">Page not found</h1>
      <p className="mt-4 text-slate-500">
        The page may have moved or the address is incorrect.
      </p>
      <Link className="btn-primary mt-7" to="/">
        Return home
      </Link>
    </section>
  );
}
