import { useEffect, useMemo, useRef, useState } from "react";
import {
  ChevronDown,
  Copy,
  GitFork as Github,
  Menu,
  Moon,
  Sun,
  X,
} from "lucide-react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { AnalyticsConsent } from "../components/AnalyticsConsent";
import { FeedbackWidget } from "../components/FeedbackWidget";
import { PageAnalytics } from "../components/PageAnalytics";
import {
  captureProductEvent,
  openAnalyticsChoices,
  routeTemplateForPath,
} from "../lib/posthog";

const navigation = [
  ["/", "Home"],
  ["/contexts", "Contexts"],
];

const AIBIM_LOGO = `${import.meta.env.BASE_URL || "/"}aibim-logo.svg`;

function ThemeToggle() {
  const [dark, setDark] = useState(
    () =>
      localStorage.theme === "dark" ||
      (!localStorage.theme &&
        matchMedia("(prefers-color-scheme: dark)").matches),
  );
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.setAttribute(
      "data-theme",
      dark ? "dark" : "light",
    );
    localStorage.theme = dark ? "dark" : "light";
  }, [dark]);
  return (
    <button
      className="theme-toggle"
      aria-label="Toggle theme"
      onClick={() => setDark(!dark)}
    >
      {dark ? <Sun size={17} /> : <Moon size={17} />}
    </button>
  );
}

function McpMenu({ navigationSurface }) {
  const [open, setOpen] = useState(false),
    [client, setClient] = useState("cursor"),
    [copied, setCopied] = useState(false),
    menuRef = useRef(null);
  const endpoint =
    typeof globalThis.window === "undefined"
      ? "https://ai-supply-chain-trust.aibim.ai/mcp"
      : `${globalThis.window.location.origin}/mcp`;
  const config = useMemo(() => {
    if (client === "codex") return `codex mcp add securitycontext ${endpoint}`;
    if (client === "claude")
      return `claude mcp add --transport http securitycontext ${endpoint}`;
    if (client === "vscode")
      return JSON.stringify(
        { servers: { securitycontext: { type: "http", url: endpoint } } },
        null,
        2,
      );
    return JSON.stringify(
      { mcpServers: { securitycontext: { url: endpoint } } },
      null,
      2,
    );
  }, [client, endpoint]);

  useEffect(() => {
    function close(event) {
      if (!menuRef.current || menuRef.current.contains(event.target)) return;
      setOpen(false);
    }
    function escape(event) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("click", close);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("click", close);
      document.removeEventListener("keydown", escape);
    };
  }, []);

  async function copyConfig() {
    try {
      if (globalThis.navigator?.clipboard?.writeText)
        await globalThis.navigator.clipboard.writeText(config);
      else {
        const area = globalThis.document.createElement("textarea");
        area.value = config;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.left = "-9999px";
        globalThis.document.body.appendChild(area);
        area.select();
        globalThis.document.execCommand("copy");
        area.remove();
      }
      setCopied(true);
      captureProductEvent("mcp_config_copied", {
        mcp_client: client,
        navigation_surface: navigationSurface,
      });
      globalThis.setTimeout(() => setCopied(false), 1400);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="mcp-menu" ref={menuRef} data-mcp-menu>
      <button
        className="mcp-trigger"
        id="mcpMenuButton"
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open ? "true" : "false"}
        onClick={() =>
          setOpen((value) => {
            const next = !value;
            if (next) {
              captureProductEvent("mcp_setup_opened", {
                mcp_client_default: client,
                navigation_surface: navigationSurface,
                context_available:
                  routeTemplateForPath(globalThis.location?.pathname) ===
                  "/r/:owner/:repository",
              });
            }
            return next;
          })
        }
      >
        <span>MCP</span>
        <ChevronDown aria-hidden="true" />
      </button>
      <div
        className="mcp-popover"
        id="mcpMenuPanel"
        role="dialog"
        aria-label="MCP configuration"
        data-open={open ? "true" : "false"}
      >
        <div className="mcp-popover-head">
          <span className="eyebrow">Agent endpoint</span>
          <strong>Security context MCP</strong>
          <p>
            Use the same endpoint from Cursor, Claude, Codex, VS Code, or any
            HTTP MCP client.
          </p>
        </div>
        <div className="mcp-endpoint-row">
          <code>{endpoint}</code>
          <button className="copy-chip" type="button" onClick={copyConfig}>
            <Copy size={13} />
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <select
          className="mcp-client-select"
          aria-label="MCP client"
          value={client}
          onChange={(event) => setClient(event.target.value)}
        >
          <option value="cursor">Cursor</option>
          <option value="claude">Claude</option>
          <option value="codex">Codex</option>
          <option value="vscode">VS Code</option>
          <option value="other">Other</option>
        </select>
        <pre className="mcp-config" id="mcpConfigSnippet">
          <code>{config}</code>
        </pre>
      </div>
    </div>
  );
}

export function AppShell() {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  return (
    <div className="app-shell">
      <PageAnalytics />
      <header className="app-header">
        <div className="app-header-inner">
          <Link to="/" className="product-mark">
            <span>
              <strong className="product-title">AI Supply Chain Trust</strong>
              <small className="product-byline">
                <span>by</span>
                <img src={AIBIM_LOGO} alt="AiBiM" width="68" height="20" />
              </small>
            </span>
          </Link>
          <nav className="primary-nav">
            {navigation.map(([to, label]) => (
              <NavLink key={to} to={to} end={to === "/"}>
                {label}
              </NavLink>
            ))}
            <McpMenu navigationSurface="desktop" />
          </nav>
          <div className="header-actions">
            <a
              className="repo-link"
              href="https://github.com/aibim-ai/AI-Supply-Chain-Trust"
            >
              <Github size={16} />
              <span>GitHub</span>
            </a>
            <ThemeToggle />
            <button
              className="theme-toggle mobile-menu-button"
              onClick={() => setMenuOpen(!menuOpen)}
              aria-label="Toggle menu"
            >
              {menuOpen ? <X /> : <Menu />}
            </button>
          </div>
        </div>
        {menuOpen && (
          <nav className="mobile-nav">
            {navigation.map(([to, label]) => (
              <Link onClick={() => setMenuOpen(false)} key={to} to={to}>
                {label}
              </Link>
            ))}
            <McpMenu navigationSurface="mobile" />
          </nav>
        )}
      </header>
      <main id="main" className={location.pathname === "/" ? "home-main" : ""}>
        <div key={location.pathname} className="page-fade">
          <Outlet />
        </div>
      </main>
      <footer className="app-footer">
        <div className="container footer-row">
          <span>AI Supply Chain Trust by AIBIM</span>
          <button type="button" onClick={openAnalyticsChoices}>
            Analytics choices
          </button>
        </div>
      </footer>
      <AnalyticsConsent />
      <FeedbackWidget />
    </div>
  );
}
