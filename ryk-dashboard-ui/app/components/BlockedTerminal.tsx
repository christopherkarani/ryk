"use client";

import { useMemo, useState } from "react";
import StatusBadge from "./StatusBadge";
import {
  filterTerminalEvents,
  formatClock,
  knownTerminalHosts,
  type TerminalEvent,
  type TerminalFeedSource,
} from "../lib/terminal-events.ts";

function decisionLabel(event: TerminalEvent): { text: string; variant: "error" | "warning" | "success" } {
  if (event.decision === "ask") return { text: "ask", variant: "warning" };
  if (event.blocked) return { text: "blocked", variant: "error" };
  return { text: "allowed", variant: "success" };
}

function Line({ event }: { event: TerminalEvent }) {
  const decision = decisionLabel(event);
  return (
    <article
      className={`grid grid-cols-1 gap-2 rounded-lg px-3 py-3 md:grid-cols-[96px_132px_minmax(0,1fr)] ${
        event.blocked ? "bg-error/[0.06]" : event.decision === "ask" ? "bg-warning/[0.06]" : "opacity-70"
      }`}
      data-blocked={event.blocked ? "true" : "false"}
      data-host={event.host}
    >
      <time className="font-mono text-[12px] text-text-tertiary" dateTime={event.timestamp}>
        {formatClock(event.timestamp)}
      </time>
      <div className="font-mono text-[12px] text-accent">{event.host}</div>
      <div className="min-w-0">
        <p className="font-mono text-[13px] text-text-primary">
          <span className="mr-2 text-text-tertiary">$</span>
          {event.target}
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <StatusBadge variant={decision.variant} dot>
            {event.blocked ? "✗ blocked" : decision.text}
          </StatusBadge>
          <StatusBadge variant={event.severity === "critical" || event.severity === "high" ? "warning" : "neutral"}>
            {event.severity}
          </StatusBadge>
          {event.rule ? <span className="font-mono text-[11px] text-text-tertiary">{event.rule}</span> : null}
        </div>
        {event.blocked || event.decision === "ask" ? (
          <p className="mt-2 text-[12px] leading-5 text-text-secondary">Why: {event.reason}</p>
        ) : null}
        {event.safer ? <p className="mt-1 font-mono text-[12px] text-success">safer: {event.safer}</p> : null}
      </div>
    </article>
  );
}

export default function BlockedTerminal({
  events,
  source,
  sessionId,
  workspaceRoot,
  policyMode,
  onLoadDemo,
  onShowLive,
}: {
  events: TerminalEvent[];
  source: TerminalFeedSource;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  policyMode?: string | null;
  onLoadDemo?: () => void;
  onShowLive?: () => void;
}) {
  const [host, setHost] = useState("all");
  const visible = useMemo(() => filterTerminalEvents(events, host), [events, host]);
  const hosts = knownTerminalHosts(events);
  const blocked = visible.filter((event) => event.blocked).length;
  const ask = visible.filter((event) => event.decision === "ask").length;
  const demo = source === "demo";

  return (
    <div className="space-y-6" data-ryk-blocked-terminal="1" data-terminal-source={source}>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Blocked", value: String(blocked), detail: "denied decisions on this machine", tone: "text-error" },
          { label: "Attention", value: String(ask), detail: "ask / approval required", tone: "text-warning" },
          { label: "Hosts", value: String(hosts.length), detail: hosts.join(" · ") || "waiting", tone: "text-text-primary" },
          {
            label: "Session",
            value: sessionId || "—",
            detail: workspaceRoot || "local evidence only",
            tone: "font-mono text-sm text-text-primary",
          },
        ].map((stat) => (
          <div key={stat.label} className="rounded-card border border-border bg-surface p-4">
            <p className="text-[11px] font-semibold uppercase tracking-widest text-text-tertiary">{stat.label}</p>
            <p className={`mt-2 text-2xl tracking-tight ${stat.tone}`}>{stat.value}</p>
            <p className="mt-1 truncate text-xs text-text-tertiary">{stat.detail}</p>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2" role="toolbar" aria-label="Filter by host">
          {["all", ...hosts].map((item) => (
            <button
              key={item}
              type="button"
              aria-pressed={host === item}
              onClick={() => setHost(item)}
              className={`min-h-11 rounded-full border px-4 text-xs font-medium ${
                host === item ? "border-transparent bg-accent/10 text-accent" : "border-border text-text-secondary"
              }`}
            >
              {item === "all" ? "All hosts" : item}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge variant={demo ? "warning" : source === "live" ? "success" : "neutral"} dot>
            {demo ? "DEMO fixture" : source === "live" ? "Live" : source === "error" ? "Unavailable" : "Empty"}
          </StatusBadge>
          {policyMode ? <StatusBadge variant="neutral">{policyMode}</StatusBadge> : null}
          {demo ? (
            <button
              type="button"
              onClick={onShowLive}
              className="min-h-11 rounded-md border border-border px-3 text-xs text-text-secondary hover:bg-surface-hover"
            >
              Show live feed
            </button>
          ) : (
            <button
              type="button"
              onClick={onLoadDemo}
              className="min-h-11 rounded-md border border-border px-3 text-xs text-text-secondary hover:bg-surface-hover"
            >
              Load demo
            </button>
          )}
        </div>
      </div>

      <section className="overflow-hidden rounded-[14px] border border-border bg-background-pure shadow-2xl shadow-black/40" aria-labelledby="blocked-terminal-title">
        <div className="flex h-11 items-center gap-3 border-b border-border bg-surface px-4">
          <div className="flex gap-1.5" aria-hidden="true">
            <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f57]" />
            <span className="h-2.5 w-2.5 rounded-full bg-[#febc2e]" />
            <span className="h-2.5 w-2.5 rounded-full bg-[#28c840]" />
          </div>
          <h2 id="blocked-terminal-title" className="font-mono text-xs text-text-secondary">
            localhost — blocked command stream
          </h2>
          <span className="ml-auto font-mono text-[11px] text-text-tertiary">
            {demo ? "DEMO · fixture" : `${blocked} blocked`}
          </span>
        </div>
        <div className="min-h-[28rem] space-y-1 p-4" id="terminal-stream">
          {source === "error" ? (
            <div className="grid min-h-[22rem] place-items-center text-center text-sm text-text-tertiary">
              <div>
                <p className="font-medium text-text-secondary">Could not load /api/status</p>
                <p className="mt-1">The feed stays empty. Use Load demo only if you want a labeled fixture stream.</p>
              </div>
            </div>
          ) : visible.length === 0 ? (
            <div className="grid min-h-[22rem] place-items-center text-center text-sm text-text-tertiary">
              <div>
                <p className="font-medium text-text-secondary">No blocked commands yet</p>
                <p className="mt-1">Denied shell and tool calls from this machine appear here. `ryk replay --only denied` is the CLI equivalent.</p>
              </div>
            </div>
          ) : (
            visible.map((event) => <Line key={event.id} event={event} />)
          )}
        </div>
      </section>
    </div>
  );
}
