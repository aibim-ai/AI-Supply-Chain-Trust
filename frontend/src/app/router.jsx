import { Navigate, createBrowserRouter, useRouteError } from "react-router-dom";
import { AppShell } from "./AppShell";
import { ErrorState } from "../components/ui";
import ContextPage from "../pages/ContextPage";
import ContextsPage from "../pages/ContextsPage";
import HomePage from "../pages/HomePage";
import LeaderboardPage from "../pages/LeaderboardPage";
import LegalPage from "../pages/LegalPage";
import NotFoundPage from "../pages/NotFoundPage";
import ResultPage from "../pages/ResultPage";

function RouteErrorBoundary() {
  const error = useRouteError();
  return (
    <section className="shell py-16">
      <ErrorState error={error} />
    </section>
  );
}

export const router = createBrowserRouter(
  [
    {
      path: "/",
      element: <AppShell />,
      errorElement: <RouteErrorBoundary />,
      children: [
        { index: true, element: <HomePage /> },
        { path: "contexts", element: <ContextsPage /> },
        { path: "recent-scans", element: <Navigate to="/contexts" replace /> },
        { path: "leaderboard", element: <LeaderboardPage /> },
        { path: "result", element: <ResultPage /> },
        { path: "r/:owner/:repository", element: <ContextPage /> },
        { path: "about", element: <LegalPage type="about" /> },
        {
          path: "editorial-policy",
          element: <LegalPage type="policy" />,
        },
        { path: "privacy", element: <LegalPage type="privacy" /> },
        { path: "*", element: <NotFoundPage /> },
      ],
    },
  ],
  {
    basename: location.pathname.startsWith("/free-tools") ? "/free-tools" : "/",
  },
);
