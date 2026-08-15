import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  DEMO_TERMINAL_EVENTS,
  DEMO_HOST_ALIASES,
  filterTerminalEvents,
  knownTerminalHosts,
  resolveTerminalFeed,
  toTerminalEvents,
  wantsDemo,
} from "./terminal-events.ts";

const root = dirname(fileURLToPath(import.meta.url));
const lockedAliases = ["claude", "codex", "pi", "opencode", "openclaw", "hermes", "grok"];
const inventedHosts = ["cursor-cloud", "ryk-agent", "ryk-cloud", "cursor"];

test("empty live feed stays empty and does not load demo fixtures", () => {
  const empty = resolveTerminalFeed({ liveEvents: [], demoRequested: false });
  assert.equal(empty.source, "empty");
  assert.deepEqual(empty.events, []);
  assert.notEqual(empty.source, "demo");
});

test("status fetch failure stays empty and does not load demo fixtures", () => {
  const failed = resolveTerminalFeed({ liveEvents: null, demoRequested: false });
  assert.equal(failed.source, "error");
  assert.deepEqual(failed.events, []);
});

test("demo fixtures load only when the operator asked", () => {
  const live = toTerminalEvents([
    {
      session_id: "ses_live",
      workspace_root: "/work",
      host: "claude",
      timestamp: "2026-08-15T00:00:00.000Z",
      event_type: "shell",
      target: "rm -rf /",
      decision: "deny",
      verified: true,
      rule: "core.filesystem:rm-rf-root-home",
      reason: "Deletes everything under the root filesystem or your home directory.",
      raw: {},
    },
  ]);
  const asked = resolveTerminalFeed({ liveEvents: [], demoRequested: true });
  assert.equal(asked.source, "demo");
  assert.equal(asked.events.length, DEMO_TERMINAL_EVENTS.length);
  assert.ok(asked.events.length > 0);

  const liveFeed = resolveTerminalFeed({ liveEvents: live, demoRequested: false });
  assert.equal(liveFeed.source, "live");
  assert.equal(liveFeed.events[0]?.target, "rm -rf /");
  assert.equal(liveFeed.events[0]?.verified, true);
});

test("wantsDemo is only true for an explicit demo query", () => {
  assert.equal(wantsDemo("", ""), false);
  assert.equal(wantsDemo("?", ""), false);
  assert.equal(wantsDemo("?host=claude", "#terminal"), false);
  assert.equal(wantsDemo("?demo=1", ""), true);
  assert.equal(wantsDemo("?demo", ""), true);
  assert.equal(wantsDemo("?demo=0", ""), false);
  assert.equal(wantsDemo("?demo=false", ""), false);
});

test("demo fixtures use launch aliases and never claim verified or live", () => {
  assert.deepEqual(DEMO_HOST_ALIASES.slice().sort(), lockedAliases.slice().sort());
  for (const event of DEMO_TERMINAL_EVENTS) {
    assert.equal(event.verified, false, `${event.target} must not claim verified`);
    assert.notEqual(event.source, "live");
    assert.match(event.source, /fixture/i);
    assert.ok(lockedAliases.includes(event.host), `unexpected host ${event.host}`);
    assert.ok(!inventedHosts.includes(event.host));
  }
  const hosts = knownTerminalHosts(DEMO_TERMINAL_EVENTS);
  assert.ok(hosts.includes("claude"));
  assert.ok(hosts.includes("codex"));
  assert.equal(filterTerminalEvents(DEMO_TERMINAL_EVENTS, "missing").length, 0);
});

test("BlockedTerminal empty live feed stays an empty state, not fixtures", () => {
  const source = readFileSync(join(root, "../components/BlockedTerminal.tsx"), "utf8");
  assert.match(source, /No blocked commands yet/);
  assert.match(source, /blocked command stream/i);
  assert.match(source, /visible\.length === 0/);
  assert.match(source, /source === "error"/);
  assert.doesNotMatch(source, /ses_cloud_7f3a91/);
  assert.doesNotMatch(source, /events\.length \? events : DEMO/);
  assert.doesNotMatch(source, /ryk@cloud/);
});

test("BlockedTerminal demo chrome is labeled fixture, not Live", () => {
  const source = readFileSync(join(root, "../components/BlockedTerminal.tsx"), "utf8");
  assert.match(source, /DEMO fixture/);
  assert.match(source, /source === "demo"/);
  assert.match(source, /source === "live" \? "Live"/);
  assert.doesNotMatch(source, /cursor-cloud/);
  assert.doesNotMatch(source, /ryk-agent/);
  assert.doesNotMatch(source, /ryk@cloud/);
});

test("dashboard UIs do not silent-demo on empty feed or fetch failure", () => {
  const files = [
    join(root, "terminal-events.ts"),
    join(root, "../components/BlockedTerminal.tsx"),
    join(root, "../terminal/page.tsx"),
    join(root, "../../../src/dashboard/assets/app.js"),
  ];
  const silentPatterns = [
    /events\.length\s*\?\s*events\s*:\s*DEMO/,
    /if\s*\(\s*!.*events\.length\)\s*loadDemo/,
    /catch\s*\{[\s\S]{0,80}loadDemo\s*\(/,
    /ses_cloud_7f3a91/,
    /cursor-cloud/,
    /ryk-agent/,
    /ryk@cloud/,
  ];
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    for (const pattern of silentPatterns) {
      assert.equal(pattern.test(source), false, `${file} still matches ${pattern}`);
    }
  }
});
