/**
 * File IPC for parent-forward policy ask + session tool grants.
 * See planning/handoffs/subagent-ask-mcp/ADR-ipc.md.
 */
import {
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

export const PRODUCT_NAME = "Rykan V";
export const DISPLAY_BRAND = "RYKAN V";
/** Status bar key — no space (Pi status id). */
export const STATUS_KEY = "rykanv";
/** Transcript customType for decision cards. */
export const DECISION_CUSTOM_TYPE = "rykanv-decision";
/** Widget dock key. */
export const BLOCK_WIDGET_KEY = "rykanv-block";

/** Canonical select labels (policy + protocol). */
export const LABEL_ALLOW_ONCE = "Allow once";
export const LABEL_DENY = "Deny";
export const LABEL_DISABLE_SESSION = "Disable Rykan V for this session";
export const LABEL_SHOW_WHY = "Show why";
export const LABEL_PROTOCOL_SESSION_ALLOW = "Allow for this session";

export type ParentAskChoice =
	| "block"
	| "run_once"
	| "disable_session"
	| "show_reason"
	| "allow_session_tool";

export type ParentAskRequest = {
	v: 1;
	id: string;
	parent_session: string;
	child_session?: string;
	tool: string;
	reason: string;
	command_or_name: string;
	created_at_ms: number;
	timeout_ms: number;
};

export type ParentAskResponse = {
	v: 1;
	id: string;
	choice: ParentAskChoice;
	decided_at_ms: number;
};

export type SessionGrants = {
	tools: string[];
	updated_at_ms: number;
};

export type ParentAskFs = {
	existsSync: (path: string) => boolean;
	mkdirSync: (
		path: string,
		opts?: { recursive?: boolean; mode?: number },
	) => void;
	writeFileSync: (
		path: string,
		data: string,
		opts?: { mode?: number },
	) => void;
	readFileSync: (path: string, encoding: "utf8") => string;
	readdirSync: (path: string) => string[];
	renameSync: (from: string, to: string) => void;
	rmSync: (path: string, opts?: { recursive?: boolean; force?: boolean }) => void;
};

export type SleepFn = (ms: number) => Promise<void>;
export type NowFn = () => number;

const DEFAULT_FS: ParentAskFs = {
	existsSync,
	mkdirSync,
	writeFileSync,
	readFileSync,
	readdirSync,
	renameSync,
	rmSync,
};

export const DEFAULT_PARENT_ASK_TIMEOUT_MS = 60_000;
export const DEFAULT_PARENT_ASK_POLL_MS = 200;
export const SESSION_GRANT_OPTION = "Allow this tool for this session";

const CHOICES = new Set<ParentAskChoice>([
	"block",
	"run_once",
	"disable_session",
	"show_reason",
	"allow_session_tool",
]);

export function parentAskTimeoutMs(
	env: NodeJS.ProcessEnv = process.env,
): number {
	const raw = env.RYK_PI_PARENT_ASK_TIMEOUT_MS?.trim();
	if (!raw) return DEFAULT_PARENT_ASK_TIMEOUT_MS;
	const n = Number(raw);
	if (!Number.isFinite(n) || n < 1_000) return DEFAULT_PARENT_ASK_TIMEOUT_MS;
	return Math.min(Math.floor(n), 600_000);
}

/** Sanitize session id for a single path segment (no traversal). */
export function sanitizeSessionId(sessionId: string): string {
	const trimmed = sessionId.trim();
	const cleaned = trimmed.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 128);
	return cleaned.length > 0 ? cleaned : "unknown";
}

/**
 * Resolve IPC root. Prefer XDG_RUNTIME_DIR, then ~/.local/state, then tmp.
 * Override with RYK_PI_ASK_ROOT for tests.
 */
export function resolvePiAskRoot(
	env: NodeJS.ProcessEnv = process.env,
	fsApi: ParentAskFs = DEFAULT_FS,
): string {
	const override = env.RYK_PI_ASK_ROOT?.trim();
	if (override) return override;

	const xdg = env.XDG_RUNTIME_DIR?.trim();
	if (xdg) {
		const root = join(xdg, "ryk", "pi-ask");
		ensureDir(root, fsApi);
		return root;
	}

	const home = env.HOME?.trim() || homedir();
	if (home) {
		const root = join(home, ".local", "state", "ryk", "pi-ask");
		ensureDir(root, fsApi);
		return root;
	}

	const root = join(tmpdir(), "ryk-pi-ask");
	ensureDir(root, fsApi);
	return root;
}

export function parentAskDir(
	root: string,
	parentSessionId: string,
	fsApi: ParentAskFs = DEFAULT_FS,
): string {
	const dir = join(root, sanitizeSessionId(parentSessionId));
	ensureDir(dir, fsApi);
	return dir;
}

/** Seatbelt EPERM on lstat/mkdir must not escape — Pi exits on uncaughtException. */
function safeExists(path: string, fsApi: ParentAskFs): boolean {
	try {
		return fsApi.existsSync(path);
	} catch {
		return false;
	}
}

/**
 * Best-effort 0700 mkdir. Seatbelt/empty-backpack EPERM must not throw:
 * Pi treats an uncaught mkdir as uncaughtException and exits.
 */
function ensureDir(path: string, fsApi: ParentAskFs): void {
	if (safeExists(path, fsApi)) return;
	try {
		fsApi.mkdirSync(path, { recursive: true, mode: 0o700 });
	} catch {
		// Caller treats a missing dir as empty / write-fail-closed.
	}
}

function atomicWriteJson(
	path: string,
	value: unknown,
	fsApi: ParentAskFs,
): void {
	const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
	fsApi.writeFileSync(tmp, `${JSON.stringify(value, null, 0)}\n`, {
		mode: 0o600,
	});
	fsApi.renameSync(tmp, path);
}

export function requestPath(dir: string, id: string): string {
	return join(dir, `req-${id}.json`);
}

export function responsePath(dir: string, id: string): string {
	return join(dir, `res-${id}.json`);
}

export function grantsPath(dir: string): string {
	return join(dir, "grants.json");
}

export function writeAskRequest(
	dir: string,
	request: ParentAskRequest,
	fsApi: ParentAskFs = DEFAULT_FS,
): string {
	const path = requestPath(dir, request.id);
	atomicWriteJson(path, request, fsApi);
	return path;
}

export function writeAskResponse(
	dir: string,
	response: ParentAskResponse,
	fsApi: ParentAskFs = DEFAULT_FS,
): string {
	const path = responsePath(dir, response.id);
	atomicWriteJson(path, response, fsApi);
	// Tombstone request so parent does not re-prompt.
	const req = requestPath(dir, response.id);
	if (safeExists(req, fsApi)) {
		try {
			fsApi.rmSync(req, { force: true });
		} catch {
			// best-effort
		}
	}
	return path;
}

export function readAskResponse(
	dir: string,
	id: string,
	fsApi: ParentAskFs = DEFAULT_FS,
): ParentAskResponse | null {
	const path = responsePath(dir, id);
	if (!safeExists(path, fsApi)) return null;
	try {
		const raw = fsApi.readFileSync(path, "utf8");
		const parsed = JSON.parse(raw) as ParentAskResponse;
		if (parsed?.v !== 1) return null;
		if (parsed.id !== id) return null;
		if (!CHOICES.has(parsed.choice)) return null;
		if (typeof parsed.decided_at_ms !== "number") return null;
		return parsed;
	} catch {
		return null;
	}
}

export function listPendingRequests(
	dir: string,
	fsApi: ParentAskFs = DEFAULT_FS,
): ParentAskRequest[] {
	if (!safeExists(dir, fsApi)) return [];
	let names: string[];
	try {
		names = fsApi.readdirSync(dir);
	} catch {
		return [];
	}
	const out: ParentAskRequest[] = [];
	for (const name of names) {
		if (!name.startsWith("req-") || !name.endsWith(".json")) continue;
		try {
			const raw = fsApi.readFileSync(join(dir, name), "utf8");
			const parsed = JSON.parse(raw) as ParentAskRequest;
			if (parsed?.v !== 1 || typeof parsed.id !== "string") continue;
			if (typeof parsed.tool !== "string") continue;
			if (typeof parsed.parent_session !== "string") continue;
			// Skip if response already present (race).
			if (safeExists(responsePath(dir, parsed.id), fsApi)) continue;
			out.push(parsed);
		} catch {
			// skip malformed
		}
	}
	// Oldest first.
	out.sort((a, b) => a.created_at_ms - b.created_at_ms);
	return out;
}

export async function waitForAskResponse(
	dir: string,
	id: string,
	options: {
		timeoutMs: number;
		pollMs?: number;
		signal?: AbortSignal;
		now?: NowFn;
		sleep?: SleepFn;
		fsApi?: ParentAskFs;
	},
): Promise<ParentAskResponse | null> {
	const fsApi = options.fsApi ?? DEFAULT_FS;
	const now = options.now ?? Date.now;
	const sleep =
		options.sleep ??
		((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
	const pollMs = options.pollMs ?? DEFAULT_PARENT_ASK_POLL_MS;
	const deadline = now() + options.timeoutMs;

	while (now() < deadline) {
		if (options.signal?.aborted) return null;
		const res = readAskResponse(dir, id, fsApi);
		if (res) return res;
		const remaining = deadline - now();
		if (remaining <= 0) break;
		await sleep(Math.min(pollMs, remaining));
	}
	return readAskResponse(dir, id, fsApi);
}

export function readGrants(
	dir: string,
	fsApi: ParentAskFs = DEFAULT_FS,
): SessionGrants {
	const path = grantsPath(dir);
	if (!safeExists(path, fsApi)) return { tools: [], updated_at_ms: 0 };
	try {
		const raw = fsApi.readFileSync(path, "utf8");
		const parsed = JSON.parse(raw) as SessionGrants;
		const tools = Array.isArray(parsed.tools)
			? parsed.tools.filter((t): t is string => typeof t === "string" && t.trim().length > 0)
			: [];
		return {
			tools,
			updated_at_ms:
				typeof parsed.updated_at_ms === "number" ? parsed.updated_at_ms : 0,
		};
	} catch {
		return { tools: [], updated_at_ms: 0 };
	}
}

export function writeGrants(
	dir: string,
	grants: SessionGrants,
	fsApi: ParentAskFs = DEFAULT_FS,
): void {
	atomicWriteJson(grantsPath(dir), grants, fsApi);
}

export function addSessionGrant(
	dir: string,
	toolName: string,
	nowMs: number = Date.now(),
	fsApi: ParentAskFs = DEFAULT_FS,
): void {
	const name = toolName.trim();
	if (!name) return;
	try {
		const current = readGrants(dir, fsApi);
		if (!current.tools.includes(name)) current.tools.push(name);
		current.updated_at_ms = nowMs;
		writeGrants(dir, current, fsApi);
	} catch {
		// Sandbox EPERM: grant is not persisted. Caller already decided this turn.
	}
}

export function hasSessionGrant(
	dir: string,
	toolName: string,
	fsApi: ParentAskFs = DEFAULT_FS,
): boolean {
	const name = toolName.trim();
	if (!name) return false;
	const grants = readGrants(dir, fsApi);
	return grants.tools.includes(name);
}

export function cleanupParentAskDir(
	dir: string,
	fsApi: ParentAskFs = DEFAULT_FS,
): void {
	if (!safeExists(dir, fsApi)) return;
	try {
		fsApi.rmSync(dir, { recursive: true, force: true });
	} catch {
		// best-effort
	}
}

export function parentSessionIdFromEnv(
	env: NodeJS.ProcessEnv = process.env,
): string | null {
	const parent = env.PI_SUBAGENT_PARENT_SESSION;
	if (typeof parent !== "string") return null;
	const trimmed = parent.trim();
	return trimmed.length > 0 ? trimmed : null;
}

export function mapSelectLabelToChoice(
	label: string | undefined,
): ParentAskChoice {
	switch (label) {
		case LABEL_ALLOW_ONCE:
			return "run_once";
		case LABEL_DISABLE_SESSION:
		case LABEL_PROTOCOL_SESSION_ALLOW:
			return "disable_session";
		case LABEL_SHOW_WHY:
			return "show_reason";
		case SESSION_GRANT_OPTION:
			return "allow_session_tool";
		case LABEL_DENY:
		default:
			return "block";
	}
}

export function buildAutoDenyCopy(
	sessionClass: "subagent" | "non-interactive",
	policyReason: string,
	toolLabel: string,
	opts?: { rule?: string },
): {
	title: string;
	summary: string;
	nextStep: string;
	rule: string;
	reason: string;
} {
	const cleaned =
		policyReason.trim() || `${toolLabel} requires approval`;
	const summary = `${PRODUCT_NAME}: needs approval but this session can't prompt (${sessionClass}). ${cleaned}`;
	const nextStep =
		sessionClass === "subagent"
			? "Approve in the parent Pi session, allowlist the tool in .ryk/policy.yaml mcp.allow, or re-run on main."
			: "Re-run in interactive Pi, or pre-allow the tool in policy.";
	const rule = opts?.rule ?? "rykanv:ask-no-ui";
	// Keep "auto-denied" token for audit/search; product voice is in summary.
	const reason = `${PRODUCT_NAME} auto-denied (${sessionClass}): ${cleaned}`;
	return {
		title: DISPLAY_BRAND,
		summary,
		nextStep,
		rule,
		reason,
	};
}
