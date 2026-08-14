"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchStatus } from "../lib/api";
import type { StatusResponse } from "../lib/types";
import { FeedHealthNotice } from "../lib/dashboard-mode";
import { toTerminalEvents } from "../lib/terminal-events.ts";
import { useToast } from "../hooks/useToast";
import ErrorBoundary from "../components/ErrorBoundary";
import PageHeader from "../components/PageHeader";
import CloudTerminal from "../components/CloudTerminal";

function TerminalContent() {
  const [data, setData] = useState<StatusResponse | null>(null);
  const { enqueue } = useToast();

  const load = useCallback(async () => {
    try {
      setData(await fetchStatus());
    } catch (error) {
      enqueue(error instanceof Error ? error.message : "Failed to load cloud terminal", "error");
    }
  }, [enqueue]);

  useEffect(() => {
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [load]);

  const events = useMemo(() => toTerminalEvents(data?.blocked_actions ?? []), [data]);

  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Cursor Cloud · ryk agent"
        title="Cloud Terminal"
        subtitle="Blocked commands from ryk cloud, ryk agent, and host plugins — Vercel-style local evidence."
        badge={{ text: events.length ? "live feed" : "demo ready", variant: events.length ? "success" : "accent" }}
      />
      {data ? <FeedHealthNotice status={data} /> : null}
      <CloudTerminal
        events={events}
        live={Boolean(data)}
        sessionId={data?.sessions[0]?.id}
        workspaceRoot={data?.ryk.workspace_root}
        policyMode={data?.policy?.mode}
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
