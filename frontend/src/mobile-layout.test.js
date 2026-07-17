import { readFileSync } from "node:fs";
import { URL } from "node:url";
import { describe, expect, it } from "vitest";

const responsiveCss = readFileSync(
  new URL("./index.css", import.meta.url),
  "utf8",
);

describe("mobile layout contract", () => {
  it("turns wide data tables into labelled cards below 760px", () => {
    expect(responsiveCss).toMatch(/@media \(max-width: 760px\)/);
    expect(responsiveCss).toMatch(
      /\.sc-watch td::before[\s\S]*content: attr\(data-label\)/,
    );
    expect(responsiveCss).toMatch(
      /\.data-table td[\s\S]*grid-template-columns: minmax\(82px/,
    );
    expect(responsiveCss).toMatch(
      /\.sc-watch,[\s\S]*\.sc-fixes[\s\S]*min-width: 0/,
    );
    expect(responsiveCss).toMatch(
      /@media \(max-width: 480px\)[\s\S]*grid-template-columns: 1fr/,
    );
  });

  it("supports adaptive column focus without forcing hover on touch", () => {
    expect(responsiveCss).toMatch(
      /@media \(hover: hover\) and \(pointer: fine\) and \(min-width: 1121px\)/,
    );
    expect(responsiveCss).toMatch(/\.sc-watch\[data-focus="contract"\]/);
    expect(responsiveCss).toMatch(/transition: width 220ms/);
    expect(responsiveCss).toMatch(
      /@media \(prefers-reduced-motion: reduce\)[\s\S]*transition: none/,
    );
  });

  it("keeps compact screens within the viewport", () => {
    expect(responsiveCss).toMatch(/html,[\s\S]*body[\s\S]*overflow-x: clip/);
    expect(responsiveCss).toMatch(
      /width: min\(calc\(100% - 24px\), var\(--container\)\)/,
    );
    expect(responsiveCss).toMatch(/@media \(max-width: 380px\)/);
  });
});
