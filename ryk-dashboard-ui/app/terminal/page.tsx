"use client";

import { useCallback, useEffect, useState } from "react";
import { fetchStatus } from "../lib/api";
import {
  resolveTerminalFeed,
  toTerminalEvents,
  wantsDemo,
  type TerminalEvent,
  type TerminalFeedSource,
} from "../lib/terminal-events.ts";
import { useToast } from "../hooks/useToast";
import ErrorBoundary from "../components/ErrorBoundary";
import PageHeader from "../components/PageHeader";
import BlockedTerminal from "../components/BlockedTerminal";

function TerminalContent() {
  const [liveEvents, setLiveEvents] = useState<TerminalEvent[] | null>([]);
  const [demoRequested, setDemoRequested] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [workspaceRoot, setWorkspaceRoot] = useState<string | null>(null);
  const [policyMode, setPolicyMode] = useState<string | null>(null);
  const { enqueue } = useToast();

  const load = useCallback(async () => {
    try {
      const status = await fetchStatus();
      setLiveEvents(toTerminalEvents(status.blocked_actions ?? []));
      setSessionId(status.sessions?.[0]?.id ?? null);
      setWorkspaceRoot(status.ryk?.workspace_root ?? (status.mode === "machine" ? "machine-wide" : null));
      setPolicyMode(status.policy?.mode ?? null);
    } catch (err) {
      setLiveEvents(null);
      enqueue(err instanceof Error ? err.message : "Failed to load blocked actions", "error");
    }
  }, [enqueue]);

  useEffect(() => {
    if (typeof window !== "undefined") {
      setDemoRequested(wantsDemo(window.location.search, window.location.hash));
    }
    load();
  }, [load]);

  const feed = resolveTerminalFeed({ liveEvents, demoRequested });
  const source: TerminalFeedSource = feed.source;

  return (
    <div className="space-y-8">
      <PageHeader
        title="Terminal"
        eyebrow="Local evidence"
        subtitle="Blocked commands from this machine. localhost only — not a hosted control plane."
        badge={
          source === "demo"
            ? { text: "DEMO fixture", variant: "warning" }
            : source === "live"
              ? { text: "Live", variant: "success" }
              : source === "error"
                ? { text: "Unavailable", variant: "error" }
                : { text: "Empty", variant: "neutral" }
        }
      />
      <BlockedTerminal
        events={feed.events}
        source={source}
        sessionId={source === "demo" ? "ses_fixture_demo" : sessionId}
        workspaceRoot={source === "demo" ? "(fixture)" : workspaceRoot}
        policyMode={source === "demo" ? "fixture" : policyMode}
        onLoadDemo={() => setDemoRequested(true)}
        onShowLive={() => setDemoRequested(false)}
      />
    </div>
  );
}

export default function TerminalPage() {
  return (
    <ErrorBoundary>
      <TerminalContent />
    </ErrorBoundary>
  );
}
