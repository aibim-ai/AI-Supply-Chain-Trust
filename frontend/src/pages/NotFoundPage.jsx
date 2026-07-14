import { Link } from "react-router-dom";
export default function NotFoundPage() {
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
