import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const readme = fs.readFileSync(new URL("./README.md", import.meta.url), "utf8");

test("README first-$42 copy points at live $42 checkouts, not the old $3 tip jar", () => {
  assert.doesNotMatch(readme, /starts at \$3/);
  assert.doesNotMatch(readme, /Fourteen independent \$3/);
  assert.match(readme, /agentic-ai-governance-pack\?wanted=true/);
  assert.match(readme, /tip-jar\?wanted=true/);
  assert.match(readme, /\/v1\/sponsor/);
  assert.match(readme, /store\.3labs\.io/);
  assert.match(readme, /42 USDC/);
  assert.match(readme, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
});
