export const STATUS_POLL_INTERVAL = 30000;

export const ACTION_IDS = [
  "doctor",
  "policy-check",
  "credentials-check",
  "credentials-check-github",
  "proxy-smoke",
  "policy-explain-github",
  "replay-last",
  "report-last",
  "ci-check",
  "openclaw-doctor",
  "hermes-doctor",
  "replay-denied",
  "suggest-allowlist",
  "allowlist-list",
] as const;

export type ActionId = (typeof ACTION_IDS)[number];

export const ACTION_LABELS: Record<string, string> = {
  doctor: "Run Doctor",
  "policy-check": "Policy Check",
  "credentials-check": "Credentials Check",
  "credentials-check-github": "Check GitHub PAT",
  "proxy-smoke": "Proxy Smoke Test",
  "policy-explain-github": "Explain GitHub Policy",
  "replay-last": "Replay Last Session",
  "report-last": "Report Last Session",
  "ci-check": "CI Check",
  "openclaw-doctor": "OpenClaw Doctor",
  "hermes-doctor": "Hermes Doctor",
  "replay-denied": "Replay Denied",
  "suggest-allowlist": "Suggest Allowlist",
  "allowlist-list": "List Allowlist",
};

export const ACTION_ICONS: Record<string, string> = {
  doctor: "Stethoscope",
  "policy-check": "ShieldCheck",
  "credentials-check": "KeyRound",
  "credentials-check-github": "Github",
  "proxy-smoke": "Wifi",
  "policy-explain-github": "FileText",
  "replay-last": "RotateCcw",
  "report-last": "FileBarChart",
  "ci-check": "GitBranch",
  "openclaw-doctor": "Plug",
  "hermes-doctor": "MessageSquare",
  "replay-denied": "XCircle",
};

export const VIEW_TITLES: Record<string, string> = {
  overview: "Overview",
  secretless: "Secretless",
  activity: "Activity",
  terminal: "Terminal",
  policy: "Policy",
  integrations: "Integrations",
};
