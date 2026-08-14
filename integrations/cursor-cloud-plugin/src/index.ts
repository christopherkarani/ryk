/**
 * Cursor Cloud / ryk cloud terminal host.
 *
 * Policy stays in the ryk CLI and existing Cursor `beforeShellExecution` hook.
 * This module maps those blocked decisions into Cloud Terminal events so the
 * Vercel-style UI can render them when users run `ryk agent` or `ryk cloud`.
 */

export type ToastVariant = "info" | "success" | "warning" | "error";

export type CloudTerminalEvent = {
  id: string;
  timestamp: string;
  host: string;
  source: string;
  decision: string;
  event_type: string;
  target: string;
  rule: string | null;
  reason: string;
  severity: string;
  verified: boolean;
  session_id: string;
  workspace_root: string;
  safer: string | null;
  blocked: boolean;
  attention: boolean;
};

export function looksLikeRykBlock(text: string): boolean {
  const line = text.split(/\r?\n/).map((part) => part.trim()).find(Boolean) || "";
  return /^\[ryk\]/i.test(line) || /ryk blocked/i.test(line);
}

export function cloudTerminalTitle(event: Pick<CloudTerminalEvent, "decision" | "target">): string {
  if (event.decision === "ask") return "ryk needs approval";
  if (event.decision === "deny" || event.decision === "block") return "ryk blocked";
  return "ryk";
}

export default {
  id: "ryk-cloud",
  title: "ryk Cloud Terminal",
};
