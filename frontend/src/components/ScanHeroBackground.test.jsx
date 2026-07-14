// @vitest-environment jsdom

import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ScanHeroBackground from "./ScanHeroBackground";

const animation = vi.hoisted(() => ({ callbacks: [] }));
vi.mock("../hooks/useCanvasAnimation", () => ({
  useCanvasAnimation: (draw) => {
    animation.callbacks.push(draw);
    return { current: null };
  },
}));

function drawingContext() {
  const gradient = { addColorStop: vi.fn() };
  return {
    arc: vi.fn(),
    beginPath: vi.fn(),
    clearRect: vi.fn(),
    createRadialGradient: vi.fn(() => gradient),
    fill: vi.fn(),
    fillRect: vi.fn(),
    lineTo: vi.fn(),
    moveTo: vi.fn(),
    stroke: vi.fn(),
    gradient,
  };
}

describe("ScanHeroBackground", () => {
  beforeEach(() => {
    animation.callbacks.length = 0;
  });

  it("renders both canvases and executes glow and terrain drawing", () => {
    const { container } = render(<ScanHeroBackground />);
    expect(container.querySelectorAll("canvas")).toHaveLength(2);
    expect(animation.callbacks).toHaveLength(2);

    for (const draw of animation.callbacks) {
      const context = drawingContext();
      draw(context, 320, 180, 1.25);
      expect(context.clearRect).toHaveBeenCalledWith(0, 0, 320, 180);
      expect(
        context.fill.mock.calls.length + context.fillRect.mock.calls.length,
      ).toBeGreaterThan(0);
    }
  });
});
