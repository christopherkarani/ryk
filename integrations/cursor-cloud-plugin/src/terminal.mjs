/**
 * Shared mapping from ryk blocked actions / plugin decisions
 * to Cloud Terminal lines. Pure data — no IO.
 */

export const RISK_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

const RULE_RISK = {
  "rm-rf-root-home": "critical",
  "rm-rf-relative-root": "critical",
  "dd-to-disk": "critical",
  "mkfs-format": "critical",
  "force-push": "high",
  "chmod-777": "high",
  "shutdown-poweroff": "high",
  "curl-pipe-shell": "high",
  "history-cleanup": "high",
  "sudo-escalation": "high",
  "cloud-metadata": "critical",
};

const RULE_REASON = {
  "rm-rf-root-home": "Deletes everything under the root filesystem or your home directory.",
  "rm-rf-relative-root": "Recursive deletion of a root-like path.",
  "force-push": "Force-pushes overwrite remote history and cannot be undone.",
  "dd-to-disk": "Writes directly to a block device, which can destroy the disk.",
  "chmod-777": "Grants world write access, making the path tamperable by anyone.",
  "shutdown-poweroff": "Powers off or reboots the machine.",
  "mkfs-format": "Formats a filesystem, destroying all data on it.",
  "sudo-escalation": "Escalates privileges; sudo is restricted by policy.",
  "curl-pipe-shell": "Pipes a remote script straight into a shell (untrusted execution).",
  "history-cleanup": "Erases shell history, hiding evidence of activity.",
  "cloud-metadata": "Cloud metadata endpoints are denied by default.",
};

export function bareRule(rule) {
  if (!rule) return null;
  const idx = rule.lastIndexOf(":");
  return idx === -1 ? rule : rule.slice(idx + 1);
}

export function riskForRule(rule) {
  const key = bareRule(rule);
  if (key && RULE_RISK[key]) return RULE_RISK[key];
  if (rule && /metadata|id_rsa|\.env|secret/i.test(rule)) return "critical";
  return "medium";
}

export function reasonForRule(rule, fallback) {
  if (fallback && fallback.trim()) return fallback;
  const key = bareRule(rule);
  if (key && RULE_REASON[key]) return RULE_REASON[key];
  return "Matched a deny rule in your ryk policy.";
}

export function isBlockedDecision(decision) {
  return decision === "deny" || decision === "block" || decision === "error";
}

export function isAttentionDecision(decision) {
  return isBlockedDecision(decision) || decision === "ask";
}

export function looksLikeRykBlock(text) {
  if (typeof text !== "string") return false;
  const line = text.split(/\r?\n/).map((part) => part.trim()).find(Boolean) || "";
  return /^\[ryk\]/i.test(line) || /ryk blocked/i.test(line);
}

export function knownHosts(events) {
  return Array.from(new Set(events.map((event) => event.host || "unknown"))).sort();
}

export function filterEventsByHost(events, host) {
  if (!host || host === "all") return events;
  return events.filter((event) => (event.host || "unknown") === host);
}

export function filterBlocked(events) {
  return events.filter((event) => isAttentionDecision(event.decision));
}

/**
 * Normalize a dashboard BlockedAction or plugin fixture event into a terminal line.
 */
export function toTerminalEvent(action, index = 0) {
  const decision = action.decision || "deny";
  const rule = action.rule ?? null;
  const host = action.host || "unknown";
  return {
    id: action.id || `${action.session_id || "session"}-${action.timestamp || index}-${index}`,
    timestamp: action.timestamp || new Date().toISOString(),
    host,
    source: action.source || inferSource(host),
    decision,
    event_type: action.event_type || "shell",
    target: action.target || "",
    rule,
    reason: reasonForRule(rule, action.reason),
    severity: action.severity || riskForRule(rule),
    verified: Boolean(action.verified),
    session_id: action.session_id || "",
    workspace_root: action.workspace_root || "",
    safer: action.safer || null,
    blocked: isBlockedDecision(decision),
    attention: isAttentionDecision(decision),
  };
}

export function toTerminalEvents(actions) {
  return (actions || []).map((action, index) => toTerminalEvent(action, index));
}

export function inferSource(host) {
  if (host === "cursor-cloud" || host === "ryk-cloud") return "ryk cloud";
  if (host === "ryk-agent" || host === "ryk") return "ryk agent";
  return "plugin";
}

export function formatClock(timestamp) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp || "—";
  return date.toISOString().slice(11, 23);
}

export function blockedCount(events) {
  return events.filter((event) => event.blocked || isBlockedDecision(event.decision)).length;
}

export function summarize(events) {
  const blocked = blockedCount(events);
  const hosts = knownHosts(events);
  return {
    total: events.length,
    blocked,
    ask: events.filter((event) => event.decision === "ask").length,
    hosts,
    last: events.length ? events[events.length - 1] : null,
  };
}
