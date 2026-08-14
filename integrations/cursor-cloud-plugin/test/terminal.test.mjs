import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  bareRule,
  blockedCount,
  filterBlocked,
  filterEventsByHost,
  inferSource,
  looksLikeRykBlock,
  reasonForRule,
  riskForRule,
  summarize,
  toTerminalEvents,
} from "../src/terminal.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(root, "../fixtures/blocked-commands.json"), "utf8"),
);

test("demo fixture includes ryk cloud and ryk agent blocked commands", () => {
  const hosts = new Set(fixture.events.map((event) => event.host));
  assert.ok(hosts.has("cursor-cloud"));
  assert.ok(hosts.has("ryk-agent"));
  assert.ok(fixture.events.some((event) => event.target.includes("curl") && event.decision === "deny"));
  assert.ok(fixture.events.some((event) => event.target.includes(".env") && event.decision === "deny"));
  assert.ok(fixture.events.some((event) => event.target.includes("169.254.169.254")));
});

test("toTerminalEvents marks deny as blocked and preserves command text", () => {
  const events = toTerminalEvents(fixture.events);
  const pipe = events.find((event) => event.target.includes("install.sh"));
  assert.equal(pipe.blocked, true);
  assert.equal(pipe.decision, "deny");
  assert.equal(pipe.host, "cursor-cloud");
  assert.match(pipe.reason, /remote script/i);
  assert.equal(pipe.severity, "high");
  assert.match(pipe.safer, /less/);
});

test("host filter isolates cursor-cloud denials", () => {
  const events = toTerminalEvents(fixture.events);
  const cloud = filterEventsByHost(events, "cursor-cloud");
  assert.ok(cloud.length >= 3);
  assert.ok(cloud.every((event) => event.host === "cursor-cloud"));
  assert.equal(filterEventsByHost(events, "missing").length, 0);
});

test("blocked count ignores the allowed git status line", () => {
  const events = toTerminalEvents(fixture.events);
  assert.ok(blockedCount(events) < events.length);
  assert.equal(filterBlocked(events).every((event) => event.decision !== "allow"), true);
  const summary = summarize(events);
  assert.equal(summary.total, events.length);
  assert.ok(summary.blocked >= 6);
  assert.ok(summary.hosts.includes("cursor-cloud"));
});

test("rule helpers stay aligned with the deny-panel reason table", () => {
  assert.equal(bareRule("core.shell:curl-pipe-shell"), "curl-pipe-shell");
  assert.equal(riskForRule("core.filesystem:rm-rf-root-home"), "critical");
  assert.match(reasonForRule("core.git:force-push"), /overwrite remote history/);
  assert.equal(inferSource("cursor-cloud"), "ryk cloud");
  assert.equal(inferSource("ryk-agent"), "ryk agent");
  assert.equal(inferSource("opencode"), "plugin");
});

test("looksLikeRykBlock matches plugin toast and hook copy", () => {
  assert.equal(looksLikeRykBlock("ryk blocked this command."), true);
  assert.equal(looksLikeRykBlock("[ryk] deny: cat .env"), true);
  assert.equal(looksLikeRykBlock("npm test"), false);
});

test("standalone terminal UI names the cloud stream and blocked state", () => {
  const html = readFileSync(join(root, "../ui/index.html"), "utf8");
  const css = readFileSync(join(root, "../ui/terminal.css"), "utf8");
  assert.match(html, /Cloud Terminal/);
  assert.match(html, /blocked command stream/);
  assert.match(html, /data-ryk-cloud-terminal/);
  assert.match(css, /#0070f3/);
  assert.match(css, /#ff4d4d/);
});
