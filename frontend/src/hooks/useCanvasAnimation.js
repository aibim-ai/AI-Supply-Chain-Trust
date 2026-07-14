import { useRef, useEffect } from "react";

export function useCanvasAnimation(draw) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId = 0;
    const startTime = performance.now();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const frameInterval = 1000 / 30;
    let lastFrame = 0;
    let width = 0;
    let height = 0;
    let isVisible = true;
    let isRunning = false;

    function resize() {
      const parent = canvas.parentElement;
      if (!parent) return;
      const w = parent.clientWidth;
      const h = parent.clientHeight;
      if (w === width && h === height) return;
      width = w;
      height = h;
      canvas.width = Math.max(1, Math.floor(w * dpr));
      canvas.height = Math.max(1, Math.floor(h * dpr));
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    function drawFrame(now) {
      const elapsed = (now - startTime) * 0.001;
      draw(ctx, width, height, elapsed);
    }

    function tick(now) {
      if (!isRunning) return;
      if (document.hidden || !isVisible) {
        isRunning = false;
        return;
      }
      if (now - lastFrame < frameInterval) {
        animId = requestAnimationFrame(tick);
        return;
      }
      lastFrame = now;
      drawFrame(now);
      animId = requestAnimationFrame(tick);
    }

    function start() {
      if (isRunning || document.hidden || !isVisible) return;
      isRunning = true;
      animId = requestAnimationFrame(tick);
    }

    function stop() {
      isRunning = false;
      if (animId) cancelAnimationFrame(animId);
    }

    function handleVisibilityChange() {
      if (document.hidden) stop();
      else start();
    }

    resize();

    const reducedMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    ).matches;
    if (reducedMotion) {
      draw(ctx, width, height, 0);
      window.addEventListener("resize", resize);
      return () => window.removeEventListener("resize", resize);
    }

    const intersectionObserver =
      "IntersectionObserver" in window
        ? new IntersectionObserver(
            ([entry]) => {
              isVisible = entry.isIntersecting;
              if (isVisible) start();
              else stop();
            },
            { threshold: 0.01 },
          )
        : null;
    intersectionObserver?.observe(canvas);

    const resizeObserver =
      "ResizeObserver" in window && canvas.parentElement
        ? new ResizeObserver(() => {
            resize();
            if (!isRunning && isVisible) drawFrame(performance.now());
          })
        : null;
    if (canvas.parentElement) resizeObserver?.observe(canvas.parentElement);

    start();
    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      stop();
      intersectionObserver?.disconnect();
      resizeObserver?.disconnect();
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [draw]);

  return canvasRef;
}
