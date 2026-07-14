import { MessageSquare, Send, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { trustApi } from "../lib/api-client";

export const OPEN_FEEDBACK_EVENT = "ai-trust:open-feedback";

export function openFeedback(repository = "") {
  globalThis.dispatchEvent(
    new globalThis.CustomEvent(OPEN_FEEDBACK_EVENT, {
      detail: { repository },
    }),
  );
}

export function FeedbackWidget() {
  const [open, setOpen] = useState(false);
  const [repository, setRepository] = useState("");
  const [status, setStatus] = useState({ state: "idle", message: "" });
  const dialogRef = useRef(null);

  useEffect(() => {
    function show(event) {
      setRepository(event.detail?.repository || "");
      setStatus({ state: "idle", message: "" });
      setOpen(true);
    }
    globalThis.addEventListener(OPEN_FEEDBACK_EVENT, show);
    return () => globalThis.removeEventListener(OPEN_FEEDBACK_EVENT, show);
  }, []);

  useEffect(() => {
    if (open) dialogRef.current?.querySelector("textarea")?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    function escape(event) {
      if (event.key === "Escape") setOpen(false);
    }
    globalThis.addEventListener("keydown", escape);
    return () => globalThis.removeEventListener("keydown", escape);
  }, [open]);

  async function submit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new globalThis.FormData(form);
    setStatus({ state: "sending", message: "" });
    try {
      await trustApi.feedback({
        category: data.get("category"),
        message: data.get("message"),
        website: data.get("website"),
        repo: repository || undefined,
        page: globalThis.location.pathname,
      });
      setStatus({ state: "sent", message: "Thanks — your feedback was sent." });
      form.reset();
    } catch (error) {
      setStatus({ state: "error", message: error.message });
    }
  }

  return (
    <>
      <button
        className="feedback-rail"
        type="button"
        onClick={() => openFeedback()}
        aria-label="Send feedback"
      >
        <MessageSquare size={16} />
        <span>Feedback</span>
      </button>
      {open && (
        <div
          className="feedback-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setOpen(false);
          }}
        >
          <section
            className="feedback-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="feedback-title"
            ref={dialogRef}
          >
            <header>
              <div>
                <span className="eyebrow">Product feedback</span>
                <h2 id="feedback-title">Tell us what you found</h2>
              </div>
              <button
                className="theme-toggle"
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close feedback"
              >
                <X size={18} />
              </button>
            </header>
            <form onSubmit={submit}>
              {repository && <p className="feedback-repo">{repository}</p>}
              <label>
                Category
                <select name="category" defaultValue="data">
                  <option value="data">Incorrect or missing data</option>
                  <option value="bug">Bug</option>
                  <option value="idea">Idea</option>
                  <option value="other">Other</option>
                </select>
              </label>
              <label>
                Message
                <textarea
                  name="message"
                  minLength="10"
                  maxLength="2000"
                  rows="6"
                  required
                  placeholder="What happened, and what did you expect?"
                />
              </label>
              <label className="feedback-honeypot" aria-hidden="true">
                Website
                <input name="website" tabIndex="-1" autoComplete="off" />
              </label>
              {status.message && (
                <p
                  className="feedback-status"
                  data-state={status.state}
                  role="status"
                >
                  {status.message}
                </p>
              )}
              <div className="feedback-actions">
                <button
                  className="button button-secondary"
                  type="button"
                  onClick={() => setOpen(false)}
                >
                  Cancel
                </button>
                <button
                  className="button button-primary"
                  type="submit"
                  disabled={status.state === "sending"}
                >
                  <Send size={15} />
                  {status.state === "sending" ? "Sending…" : "Send feedback"}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
    </>
  );
}
