// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AppShell } from "./AppShell";

describe("AppShell", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.stubGlobal("matchMedia", () => ({ matches: false }));
    Object.defineProperty(globalThis.navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  function renderShell() {
    return render(
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<div>Home body</div>} />
            <Route path="contexts" element={<div>Contexts body</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
  }

  it("keeps the product mark inline and supports theme and mobile navigation", async () => {
    const user = userEvent.setup();
    renderShell();

    expect(screen.getByText("AI Supply Chain Trust")).toBeTruthy();
    expect(screen.getByAltText("AiBiM").getAttribute("src")).toContain(
      "aibim-logo.svg",
    );
    await user.click(screen.getByLabelText("Toggle theme"));
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(localStorage.theme).toBe("dark");

    await user.click(screen.getByLabelText("Toggle menu"));
    expect(screen.getAllByText("Contexts").length).toBeGreaterThan(1);
    await user.click(screen.getAllByText("Contexts").at(-1));
    expect(await screen.findByText("Contexts body")).toBeTruthy();
  });

  it("changes MCP configuration by client and copies the exact command", async () => {
    const user = userEvent.setup();
    const writeText = vi.spyOn(globalThis.navigator.clipboard, "writeText");
    renderShell();

    await user.click(screen.getByRole("button", { name: "MCP" }));
    await user.selectOptions(screen.getByLabelText("MCP client"), "codex");
    const command = `codex mcp add securitycontext ${window.location.origin}/mcp`;
    expect(screen.getByText(command)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: /copy/i }));
    expect(writeText).toHaveBeenCalledWith(command);
    expect(await screen.findByText("Copied")).toBeTruthy();
  });
});
