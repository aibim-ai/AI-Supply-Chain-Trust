// @vitest-environment jsdom

import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useCanvasAnimation } from "./useCanvasAnimation";

const context = { setTransform: vi.fn() };
let frame;
let intersectionCallback;

class IntersectionObserverStub {
  constructor(callback) {
    intersectionCallback = callback;
  }
  observe = vi.fn();
  disconnect = vi.fn();
}

class ResizeObserverStub {
  observe = vi.fn();
  disconnect = vi.fn();
}

function Harness({ draw }) {
  const ref = useCanvasAnimation(draw);
  return (
    <div data-testid="parent">
      <canvas ref={ref} />
    </div>
  );
}

describe("useCanvasAnimation", () => {
  beforeEach(() => {
    frame = undefined;
    intersectionCallback = undefined;
    context.setTransform.mockClear();
    vi.spyOn(
      globalThis.HTMLCanvasElement.prototype,
      "getContext",
    ).mockReturnValue(context);
    vi.stubGlobal(
      "requestAnimationFrame",
      vi.fn((callback) => {
        frame = callback;
        return 41;
      }),
    );
    vi.stubGlobal("cancelAnimationFrame", vi.fn());
    vi.stubGlobal("IntersectionObserver", IntersectionObserverStub);
    vi.stubGlobal("ResizeObserver", ResizeObserverStub);
    vi.stubGlobal("matchMedia", () => ({ matches: false }));
    Object.defineProperty(window, "devicePixelRatio", {
      configurable: true,
      value: 2,
    });
    Object.defineProperty(globalThis.HTMLElement.prototype, "clientWidth", {
      configurable: true,
      get: () => 320,
    });
    Object.defineProperty(globalThis.HTMLElement.prototype, "clientHeight", {
      configurable: true,
      get: () => 180,
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("sizes the canvas, draws animation frames, pauses when hidden, and cleans up", () => {
    const draw = vi.fn();
    const { container, unmount } = render(<Harness draw={draw} />);
    const canvas = container.querySelector("canvas");

    expect(canvas.width).toBe(640);
    expect(canvas.height).toBe(360);
    expect(context.setTransform).toHaveBeenCalledWith(2, 0, 0, 2, 0, 0);
    expect(requestAnimationFrame).toHaveBeenCalled();

    frame(performance.now() + 40);
    expect(draw).toHaveBeenCalledWith(context, 320, 180, expect.any(Number));
    intersectionCallback([{ isIntersecting: false }]);
    expect(cancelAnimationFrame).toHaveBeenCalledWith(41);

    unmount();
    expect(cancelAnimationFrame).toHaveBeenCalled();
  });

  it("draws once and avoids animation when reduced motion is requested", () => {
    vi.stubGlobal("matchMedia", () => ({ matches: true }));
    const draw = vi.fn();

    render(<Harness draw={draw} />);

    expect(draw).toHaveBeenCalledWith(context, 320, 180, 0);
    expect(requestAnimationFrame).not.toHaveBeenCalled();
  });
});
