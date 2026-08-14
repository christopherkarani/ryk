import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { CommandPaletteItems } from "./command-palette.ts";
import {
  DashboardModeContext,
  FeedHealthNotice,
  MachineContextFields,
  WorkspaceOnlyGate,
} from "./dashboard-mode.ts";
import { visibleNavigation } from "./nav.ts";
import { sessionKey } from "./types.ts";
import {
  ActivityHostFilter,
  RemediationActions,
  filterActionsByHost,
  remediationCommandsFor,
} from "../components/ActivityControls.ts";
import {
  DEMO_TERMINAL_EVENTS,
  filterTerminalEvents,
  inferSource,
  isBlockedDecision,
  reasonForRule,
  toTerminalEvents,
} from "./terminal-events.ts";

function renderInMode(mode: "machine" | "workspace", child: React.ReactNode): string {
  return renderToStaticMarkup(
    React.createElement(
      DashboardModeContext.Provider,
      { value: { mode, loading: false } },
      child,
    ),
  );
}

test("session identity includes its workspace", () => {
  assert.notEqual(
    sessionKey({ id: "same", workspace_root: "/a" }),
    sessionKey({ id: "same", workspace_root: "/b" }),
  );
});

test("machine navigation renders only global-safe destinations", () => {
  const machineLabels = visibleNavigation("machine").map((tab) => tab.label);
  const workspaceLabels = visibleNavigation("workspace").map((tab) => tab.label);
  assert.deepEqual(machineLabels, ["Overview", "Activity", "Terminal", "Integrations"]);
  assert.ok(workspaceLabels.includes("Policy"));
  assert.ok(workspaceLabels.includes("Secretless"));
  assert.ok(workspaceLabels.includes("Terminal"));
});

test("command palette renders only actions and views allowed by dashboard mode", () => {
  const machine = renderInMode("machine", React.createElement(CommandPaletteItems));
  const workspace = renderInMode("workspace", React.createElement(CommandPaletteItems));

  assert.match(machine, /Overview/);
  assert.match(machine, /Terminal/);
  assert.match(machine, /Run Doctor/);
  assert.doesNotMatch(machine, /Policy/);
  assert.doesNotMatch(machine, /Secretless/);
  assert.doesNotMatch(machine, /Credentials Check/);
  assert.doesNotMatch(machine, /CI Check/);
  assert.match(workspace, /Policy/);
  assert.match(workspace, /Secretless/);
  assert.match(workspace, /Credentials Check/);
  assert.match(workspace, /CI Check/);
});

test("workspace-only routes do not mount their controls in machine mode", () => {
  const controls = React.createElement("button", { "data-testid": "policy-save" }, "Save policy");
  const machine = renderInMode("machine", React.createElement(WorkspaceOnlyGate, null, controls));
  const workspace = renderInMode("workspace", React.createElement(WorkspaceOnlyGate, null, controls));

  assert.doesNotMatch(machine, /data-testid="policy-save"/);
  assert.match(machine, /Select a workspace/);
  assert.match(machine, /ryk dashboard --workspace/);
  assert.match(workspace, /data-testid="policy-save"/);
});

test("machine activity renders workspace, host, and degraded-feed context", () => {
  const context = renderToStaticMarkup(
    React.createElement(MachineContextFields, { workspaceRoot: "/work/a", host: "build-01" }),
  );
  const warning = renderToStaticMarkup(
    React.createElement(FeedHealthNotice, {
      status: { feed_health: { status: "degraded", skipped_lines: 3 } },
    }),
  );

  assert.match(context, /Workspace/);
  assert.match(context, /\/work\/a/);
  assert.match(context, /Host/);
  assert.match(context, /build-01/);
  assert.match(warning, /skipped 3 malformed lines/);
});

const blockedActions = [
  { session_id: "a", workspace_root: "/work/a", host: "pi", timestamp: "1", event_type: "deny", target: "shell command (redacted)", decision: "deny", verified: true, rule: "core.shell:pipe", reason: "blocked", raw: {} },
  { session_id: "b", workspace_root: "/work/b", host: "hermes", timestamp: "2", event_type: "deny", target: "tool call (redacted)", decision: "ask", verified: false, rule: null, reason: "approval required", raw: {} },
];

test("activity host filtering is behavior-driven and preserves accessible targets", () => {
  assert.deepEqual(filterActionsByHost(blockedActions, "pi").map((action) => action.session_id), ["a"]);
  const markup = renderToStaticMarkup(
    React.createElement(ActivityHostFilter, { actions: blockedActions, selected: "pi", onSelect: () => {} }),
  );
  assert.match(markup, /aria-pressed="true"/);
  assert.match(markup, /min-h-11/);
  assert.match(markup, /min-w-11/);
  assert.match(markup, /focus-visible:outline/);
});

test("workspace remediation is fixed and machine mode never mounts workspace actions", () => {
  const commands = remediationCommandsFor(blockedActions[0]);
  assert.ok(commands.some((item) => item.value.includes("ryk allowlist add core.shell:pipe")));
  assert.ok(commands.some((item) => item.value === "ryk suggest-allowlist --confidence high --non-interactive"));

  const workspace = renderToStaticMarkup(React.createElement(RemediationActions, { action: blockedActions[0], mode: "workspace", onRun: () => {}, onCopy: () => {} }));
  const machine = renderToStaticMarkup(React.createElement(RemediationActions, { action: blockedActions[0], mode: "machine", onRun: () => {}, onCopy: () => {} }));
  assert.match(workspace, /Run suggest-allowlist/);
  assert.match(workspace, /List allowlist/);
  assert.match(workspace, /min-h-11/);
  assert.equal(machine, "");
});

test("legacy fallback suppresses workspace remediation markup in machine mode", () => {
  const source = readFileSync(new URL("../../../src/dashboard/assets/app.js", import.meta.url), "utf8");
  const helper = source.match(/function workspaceActionMarkup\(machineMode, markup\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(helper, "legacy fallback must define its mode-aware workspace action helper");

  const context: { workspaceResult?: string; machineResult?: string } = {};
  vm.runInNewContext(
    `${helper}; workspaceResult = workspaceActionMarkup(false, "<button>workspace</button>"); machineResult = workspaceActionMarkup(true, "<button>workspace</button>");`,
    context,
  );
  assert.equal(context.workspaceResult, "<button>workspace</button>");
  assert.equal(context.machineResult, "");
});

test("cloud terminal maps plugin denials and keeps command text visible", () => {
  const events = toTerminalEvents(blockedActions);
  assert.equal(events[0].blocked, true);
  assert.equal(events[0].target, "shell command (redacted)");
  assert.equal(inferSource("cursor-cloud"), "ryk cloud");
  assert.equal(inferSource("ryk-agent"), "ryk agent");
  assert.equal(isBlockedDecision("deny"), true);
  assert.match(reasonForRule("core.shell:curl-pipe-shell"), /remote script/);
  assert.ok(filterTerminalEvents(DEMO_TERMINAL_EVENTS, "cursor-cloud").every((event) => event.host === "cursor-cloud"));
  assert.ok(DEMO_TERMINAL_EVENTS.some((event) => event.target.includes("install.sh") && event.blocked));
});

test("cloud terminal page and component keep blocked command copy visible", () => {
  const page = readFileSync(new URL("../terminal/page.tsx", import.meta.url), "utf8");
  const component = readFileSync(new URL("../components/CloudTerminal.tsx", import.meta.url), "utf8");
  assert.match(page, /Cloud Terminal/);
  assert.match(page, /ryk cloud/);
  assert.match(component, /data-ryk-cloud-terminal/);
  assert.match(component, /blocked command stream/);
  assert.match(component, /✗ blocked/);
});

test("legacy dashboard ships a cloud terminal renderer for blocked commands", () => {
  const source = readFileSync(new URL("../../../src/dashboard/assets/app.js", import.meta.url), "utf8");
  const html = readFileSync(new URL("../../../src/dashboard/assets/index.html", import.meta.url), "utf8");
  assert.match(source, /function renderCloudTerminal/);
  assert.match(source, /cursor-cloud/);
  assert.match(source, /ryk-agent/);
  assert.match(html, /data-view="terminal"/);
  assert.match(html, /blocked command stream/);
});

test("legacy fallback never builds commands from hostile persisted remediation", () => {
  const source = readFileSync(new URL("../../../src/dashboard/assets/app.js", import.meta.url), "utf8");
  const extractRule = source.match(/function extractRuleId\(action\) \{[\s\S]*?\n\}/)?.[0];
  const remediation = source.match(/function remediationCommandsFor\(action\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(extractRule);
  assert.ok(remediation);

  const context: { commands?: Array<{ value: string }> } = {};
  vm.runInNewContext(
    `${extractRule}; ${remediation}; commands = remediationCommandsFor({ rule: "safe; touch /tmp/pwn", reason: "blocked", remediation: "ryk safe; touch /tmp/pwn" });`,
    context,
  );
  assert.deepEqual(
    Array.from(context.commands ?? [], (command) => command.value),
    ["ryk suggest-allowlist --confidence high --non-interactive"],
  );
});
