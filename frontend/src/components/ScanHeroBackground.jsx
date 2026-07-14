import { useCallback } from "react";
import { useCanvasAnimation } from "../hooks/useCanvasAnimation";

const GRID_W = 100;
const GRID_D = 80;
const CELL_SIZE = 0.35;
const FLY_SPEED = 0.8;

function getHeight(wx, wz) {
  const mountains =
    3.5 *
    Math.pow(
      Math.abs(Math.sin(wx * 0.08 + 0.7) * Math.cos(wz * 0.06 + 0.4)),
      0.7,
    ) *
    Math.sin(wx * 0.05 + wz * 0.04 + 1.0);
  const ridges =
    2.0 *
    Math.abs(Math.sin(wx * 0.15 + wz * 0.12 + 2.3)) *
    Math.cos(wx * 0.07 - wz * 0.09 + 0.5);
  const canyons =
    -2.5 *
    Math.pow(
      Math.abs(Math.cos(wx * 0.1 + 1.5) * Math.sin(wz * 0.08 + 0.9)),
      1.5,
    );
  const hills =
    1.2 * Math.sin(wx * 0.2 + wz * 0.15 + 3.1) +
    0.6 * Math.sin(wx * 0.35 + 0.8) * Math.cos(wz * 0.28 + 1.7);
  const detail =
    0.4 * Math.sin(wx * 0.7 + wz * 0.5 + 4.2) +
    0.2 * Math.sin(wx * 1.3 + wz * 0.9 + 2.0);
  return mountains + ridges + canyons + hills + detail;
}

function project(x3, y3, z3, w, h) {
  const fov = 500,
    cameraHeight = -12,
    pitch = 0.55;
  const cosP = Math.cos(pitch),
    sinP = Math.sin(pitch);
  const ry = (y3 - cameraHeight) * cosP - z3 * sinP;
  const rz = (y3 - cameraHeight) * sinP + z3 * cosP;
  if (rz <= 0.1) return null;
  const scale = fov / rz;
  return { x: w / 2 + x3 * scale, y: h * 0.38 + ry * scale, scale, z: rz };
}

function ScanTerrainCanvas() {
  const draw = useCallback((ctx, w, h, time) => {
    ctx.clearRect(0, 0, w, h);
    const isDark = document.documentElement.classList.contains("dark");
    const alphaBoost = isDark ? 1 : 1.7;
    const zOffset = time * FLY_SPEED;

    for (let gz = GRID_D - 1; gz >= 0; gz--) {
      for (let gx = 0; gx < GRID_W; gx++) {
        const localX = (gx - GRID_W / 2) * CELL_SIZE;
        const localZ = gz * CELL_SIZE;
        const worldZ = localZ + zOffset;
        const wy = -getHeight(localX, worldZ);
        const p = project(localX, wy, localZ, w, h);
        if (!p || p.x < -30 || p.x > w + 30 || p.y < -30 || p.y > h + 30)
          continue;

        const depthFade = Math.min(1, 0.15 + p.z / 30);
        const heightVal = -wy;
        const dotSize = Math.max(
          0.4,
          ((1.4 + 0.4 * Math.max(0, heightVal / 4)) * p.scale) / 35,
        );

        let r, g, b;
        if (heightVal > 3.5) {
          r = 180;
          g = 220;
          b = 255;
        } else if (heightVal > 2.0) {
          r = 6;
          g = 182;
          b = 212;
        } else if (heightVal > 1.0) {
          r = 30;
          g = 140;
          b = 220;
        } else if (heightVal > 0) {
          r = 70;
          g = 100;
          b = 235;
        } else if (heightVal > -1.0) {
          r = 99;
          g = 82;
          b = 220;
        } else {
          r = 80;
          g = 50;
          b = 180;
        }

        const alpha =
          depthFade *
          (0.08 + 0.5 * Math.max(0, (heightVal + 2) / 6)) *
          alphaBoost;

        ctx.beginPath();
        ctx.arc(p.x, p.y, dotSize, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${alpha})`;
        ctx.fill();

        if (gx < GRID_W - 1) {
          const nx = (gx + 1 - GRID_W / 2) * CELL_SIZE;
          const ny = -getHeight(nx, localZ + zOffset);
          const np = project(nx, ny, localZ, w, h);
          if (np) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(np.x, np.y);
            ctx.strokeStyle = `rgba(6,182,212,${alpha * 0.25})`;
            ctx.lineWidth = 0.4;
            ctx.stroke();
          }
        }
        if (gz < GRID_D - 1) {
          const nz = (gz + 1) * CELL_SIZE;
          const ny = -getHeight(localX, nz + zOffset);
          const np = project(localX, ny, nz, w, h);
          if (np) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(np.x, np.y);
            ctx.strokeStyle = `rgba(6,182,212,${alpha * 0.2})`;
            ctx.lineWidth = 0.4;
            ctx.stroke();
          }
        }
      }
    }
  }, []);

  const canvasRef = useCanvasAnimation(draw);
  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none z-0"
    />
  );
}

function ScanGlow() {
  const draw = useCallback((ctx, w, h, time) => {
    ctx.clearRect(0, 0, w, h);
    const isDark = document.documentElement.classList.contains("dark");
    const glowBoost = isDark ? 0 : 0.025;
    const t = time * 0.85;

    const x1 = w * (0.25 + 0.2 * Math.sin(t * 0.3));
    const y1 = h * (0.35 + 0.2 * Math.cos(t * 0.25));
    const r1 = w * (0.4 + 0.1 * Math.sin(t * 0.4));
    const g1 = ctx.createRadialGradient(x1, y1, 0, x1, y1, r1);
    g1.addColorStop(
      0,
      `rgba(99, 102, 241, ${0.08 + 0.03 * Math.sin(t * 0.5) + glowBoost})`,
    );
    g1.addColorStop(1, "transparent");
    ctx.fillStyle = g1;
    ctx.fillRect(0, 0, w, h);

    const x2 = w * (0.7 + 0.15 * Math.cos(t * 0.35 + 1));
    const y2 = h * (0.5 + 0.15 * Math.sin(t * 0.4 + 2));
    const r2 = w * (0.35 + 0.08 * Math.cos(t * 0.3));
    const g2 = ctx.createRadialGradient(x2, y2, 0, x2, y2, r2);
    g2.addColorStop(
      0,
      `rgba(6, 182, 212, ${0.06 + 0.02 * Math.cos(t * 0.6) + glowBoost})`,
    );
    g2.addColorStop(1, "transparent");
    ctx.fillStyle = g2;
    ctx.fillRect(0, 0, w, h);

    const x3 = w * (0.4 + 0.25 * Math.sin(t * 0.2 + 3));
    const y3 = h * (0.78 + 0.07 * Math.cos(t * 0.15));
    const r3 = w * (0.45 + 0.1 * Math.sin(t * 0.25 + 1));
    const g3 = ctx.createRadialGradient(x3, y3, 0, x3, y3, r3);
    g3.addColorStop(
      0,
      `rgba(99, 102, 241, ${0.05 + 0.02 * Math.sin(t * 0.35) + glowBoost})`,
    );
    g3.addColorStop(1, "transparent");
    ctx.fillStyle = g3;
    ctx.fillRect(0, 0, w, h);
  }, []);

  const canvasRef = useCanvasAnimation(draw);
  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none z-0"
    />
  );
}

export default function ScanHeroBackground() {
  return (
    <>
      <ScanGlow />
      <div
        className="absolute bottom-0 left-0 right-0 pointer-events-none z-[2]"
        style={{ height: "60%" }}
      >
        <ScanTerrainCanvas />
      </div>
    </>
  );
}
