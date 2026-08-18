import { spawn as nodeSpawn } from "node:child_process";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { accessSync, constants, existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, isAbsolute, resolve } from "node:path";
import {
	addSessionGrant,
	BLOCK_WIDGET_KEY,
	buildAutoDenyCopy,
	cleanupParentAskDir,
	DECISION_CUSTOM_TYPE,
	DISPLAY_BRAND,
	hasSessionGrant,
	LABEL_ALLOW_ONCE,
	LABEL_DENY,
	LABEL_DISABLE_SESSION,
	LABEL_PROTOCOL_SESSION_ALLOW,
	LABEL_SHOW_WHY,
	listPendingRequests,
	mapSelectLabelToChoice,
	parentAskDir,
	parentAskTimeoutMs,
	parentSessionIdFromEnv,
	PRODUCT_NAME,
	resolvePiAskRoot,
	sanitizeSessionId,
	SESSION_GRANT_OPTION,
	STATUS_KEY,
	waitForAskResponse,
	writeAskRequest,
	writeAskResponse,
	type ParentAskChoice,
	type ParentAskFs,
	type ParentAskRequest,
} from "./parent_ask.ts";
import {
	handleSecretCaptureInput,
	isSecretCaptureDisabled,
	scrubContextMessages,
} from "./secret_capture.ts";

export {
	BLOCK_WIDGET_KEY,
	DECISION_CUSTOM_TYPE,
	DISPLAY_BRAND,
	LABEL_ALLOW_ONCE,
	LABEL_DENY,
	LABEL_DISABLE_SESSION,
	LABEL_PROTOCOL_SESSION_ALLOW,
	LABEL_SHOW_WHY,
	PRODUCT_NAME,
	SESSION_GRANT_OPTION,
	STATUS_KEY,
	buildAutoDenyCopy,
	parentAskTimeoutMs,
	resolvePiAskRoot,
	sanitizeSessionId,
	hasSessionGrant,
	addSessionGrant,
	readGrants,
	listPendingRequests,
	writeAskRequest,
	writeAskResponse,
	waitForAskResponse,
	mapSelectLabelToChoice,
	parentAskDir,
	parentSessionIdFromEnv,
} from "./parent_ask.ts";

type UnavailableMode =
	| "auto"
	| "ask"
	| "noninteractive-block"
	| "strict"
	| "allow-with-warning";
type EffectiveUnavailableMode =
	| "ask"
	| "noninteractive-block"
	| "strict"
	| "allow-with-warning";

type ToolCallBlock = { block: true; reason?: string };
type ToolCallResult = ToolCallBlock | undefined;

type PiToolCallEvent = {
	toolName: string;
	input?: Record<string, unknown>;
};

type PiUI = {
	select?: (
		title: string,
		options: string[],
		opts?: { timeout?: number; signal?: AbortSignal },
	) => Promise<string | undefined>;
	confirm?: (
		title: string,
		message: string,
		opts?: { timeout?: number; signal?: AbortSignal },
	) => Promise<boolean | undefined>;
	notify?: (message: string, type?: "info" | "warning" | "error") => void;
	setStatus?: (key: string, text: string | undefined) => void;
	setWidget?: (
		key: string,
		value: undefined | string[],
		opts?: { placement?: "aboveEditor" | "belowEditor" },
	) => void;
};

type PiContext = {
	ui?: PiUI;
	cwd?: string;
	mode?: string;
	hasUI?: boolean;
	signal?: AbortSignal;
	sessionManager?: {
		getSessionId?: () => string;
	};
};

type PiAPI = {
	on: (
		event: string,
		handler: (event: any, ctx: PiContext) => Promise<any> | any,
	) => void;
	registerCommand: (
		name: string,
		options: {
			description?: string;
			handler: (
				args: string | undefined,
				ctx: PiContext,
			) => Promise<void> | void;
		},
	) => void;
	sendMessage?: (
		message: {
			customType: string;
			content: string;
			display: boolean;
			details?: unknown;
		},
		options?: {
			triggerTurn?: boolean;
			deliverAs?: "steer" | "followUp" | "nextTurn";
		},
	) => void;
	/** Optional Pi host API for custom transcript chrome (no purple default). */
	registerMessageRenderer?: (
		customType: string,
		renderer: (
			message: { content?: string; details?: unknown },
			options: { expanded?: boolean; outputPad?: number },
			theme: PiTheme,
		) => TuiComponentLike | undefined,
	) => void;
};

/** Pi theme surface used by decision cards — prefer semantic tokens over raw ANSI. */
type PiTheme = {
	fg: (name: string, text: string) => string;
	bg?: (name: string, text: string) => string;
	bold?: (text: string) => string;
	dim?: (text: string) => string;
};

type SpawnOptions = {
	stdio: ["pipe" | "ignore", "pipe" | "ignore", "pipe" | "ignore"];
	shell: false;
	signal?: AbortSignal;
	env?: NodeJS.ProcessEnv;
	cwd?: string;
};

type SpawnSyncLike = (
	file: string,
	args: string[],
	options: {
		encoding: "utf8";
		env: NodeJS.ProcessEnv;
		shell: false;
		timeout: number;
	},
) => { error?: Error; status: number | null; stdout?: string };

type ChildLike = {
	stdin?: { write: (data: string) => void; end: () => void };
	stdout?: {
		on: (event: "data", handler: (chunk: Buffer | string) => void) => void;
	};
	stderr?: {
		on: (event: "data", handler: (chunk: Buffer | string) => void) => void;
	};
	on: (
		event: "error" | "close",
		handler: ((error: Error) => void) | ((code: number | null) => void),
	) => void;
};

type SpawnLike = (
	file: string,
	args: string[],
	options: SpawnOptions,
) => ChildLike;

/**
 * Built-in Pi tools with specialized evaluators (evaluate / decide file).
 * Other tools may be name-gated via `ryk decide tool` unless passthrough.
 */
export const PROTECTED_PI_TOOLS = [
	"bash",
	"write",
	"edit",
	"read",
	"grep",
	"find",
	"ls",
] as const;
export type ProtectedPiTool = (typeof PROTECTED_PI_TOOLS)[number];

/**
 * Pi control-plane / orchestration tools with no host shell or FS side effects
 * through the standard bash/file path. Skip noisy name-only `decide tool`.
 * MCP and other custom tools still name-gate.
 */
export const PASSTHROUGH_PI_TOOLS = [
	"contact_supervisor",
	"intercom",
	"subagent",
] as const;

/** File tools that use Zig `ryk decide file` with operation write. */
const FILE_WRITE_TOOLS = new Set<string>(["write", "edit"]);
/** File tools that use Zig `ryk decide file` with operation read. */
const FILE_READ_TOOLS = new Set<string>(["read", "grep", "find", "ls"]);
/** Discovery tools can traverse/read descendants that a root-only preflight cannot prove safe. */
const BROAD_DISCOVERY_TOOLS = new Set<string>(["grep", "find", "ls"]);

export function isProtectedPiTool(
	toolName: string,
): toolName is ProtectedPiTool {
	return (PROTECTED_PI_TOOLS as readonly string[]).includes(toolName);
}

/** True for Pi orchestration tools that skip name-only decide. */
export function isPassthroughPiTool(toolName: string): boolean {
	return (PASSTHROUGH_PI_TOOLS as readonly string[]).includes(toolName);
}

/**
 * Whether a non-protected tool should hit `ryk decide tool` (name gate).
 * Protected tools use specialized evaluators; passthrough tools are allowed.
 */
export function shouldNameGateTool(toolName: string): boolean {
	const name = toolName.trim();
	if (!name) return false;
	if (isProtectedPiTool(name)) return false;
	if (isPassthroughPiTool(name)) return false;
	return true;
}

/** Honest coverage string for doctor/status surfaces (not the ask card). */
export function piCoverageLabel(): string {
	return "bash + write + edit + read policy-protected; grep + find + ls root-preflight; Pi control tools (contact_supervisor/intercom/subagent) passthrough; other custom names gated via decide tool";
}

/**
 * Path target for decide-file preflight.
 * - read/write/edit: require non-empty `path`
 * - grep/find/ls: optional `path` (Pi defaults to cwd / "."); use that default when omitted
 */
export function extractDecideFilePath(
	toolName: string,
	input: Record<string, unknown> | undefined,
): { path: string; required: boolean } | null {
	const raw = typeof input?.path === "string" ? input.path.trim() : "";
	if (toolName === "read" || FILE_WRITE_TOOLS.has(toolName)) {
		return { path: raw, required: true };
	}
	if (FILE_READ_TOOLS.has(toolName)) {
		// Pi grep/find/ls default search/list root is cwd when path is omitted.
		return { path: raw || ".", required: false };
	}
	return null;
}

export type RykEvaluateRequest = {
	schema_version: 1;
	request_id: string;
	kind: "shell_command";
	command: string;
	cwd: string;
	source: {
		host: "pi";
		tool_name: string;
		mode?: string;
		session_id?: string;
	};
};

export type RykDecideFileRequest = {
	path: string;
	operation: "read" | "write";
};

/** Custom / MCP-shaped tool names → Zig `ryk decide tool` (name only). */
export type RykDecideToolRequest = {
	name: string;
};

export type RykDecision =
	| { kind: "allow"; response: unknown }
	| { kind: "deny"; reason: string; response: unknown }
	| { kind: "ask"; reason: string; response: unknown }
	| { kind: "warn"; reason: string; response: unknown }
	| {
			kind: "error";
			reason: string;
			response?: unknown;
			error?: Error;
			/** Protocol failure class token for recovery UX (never means allow). */
			failureClass?: ProtocolFailureClass;
	  };

/** Classify decide/evaluate protocol failures for recovery UX (Phase 5). */
export type ProtocolFailureClass =
	| "timeout"
	| "malformed_json"
	| "spawn_failed"
	| "inconsistent_exit"
	| "output_too_large"
	| "unexpected";

/** Consecutive protocol failures before one-shot session degraded notify. */
export const PROTOCOL_DEGRADED_THRESHOLD = 3;

/**
 * Build a fail-closed reason that always includes a bracketed class token.
 * Never used to allow; diagnosis only.
 */
export function formatProtocolErrorReason(
	failureClass: ProtocolFailureClass,
	detail: string,
): string {
	const cleaned = sanitizeVisibleText(detail);
	return `[${failureClass}] ${cleaned}`;
}

/** Compact stdout/stderr preview for protocol diagnostics (never empty → "empty"). */
export function previewProcessOutput(text: string, maxChars = 120): string {
	const trimmed = text.replace(/\s+/g, " ").trim();
	if (!trimmed) return "empty";
	const sliced =
		trimmed.length > maxChars ? `${trimmed.slice(0, maxChars)}…` : trimmed;
	return JSON.stringify(sliced);
}

/**
 * Human-readable detail when JSON.parse(stdout) fails.
 * Includes exit + stdout/stderr previews so /ryk-doctor and the ask card are actionable.
 */
export function formatMalformedJsonDetail(
	result: Pick<RunProcessResult, "code" | "stdout" | "stderr">,
	verb: "evaluate" | "decide",
): string {
	const exit = result.code === null ? "null" : String(result.code);
	return `ryk ${verb} returned malformed JSON (exit ${exit}; stdout ${previewProcessOutput(result.stdout)}; stderr ${previewProcessOutput(result.stderr)}).`;
}

/** Extract class token from a reason string, if present. */
export function protocolFailureClassFromReason(
	reason: string,
): ProtocolFailureClass | undefined {
	const match = /^\[([a-z_]+)\]/.exec(reason.trim());
	if (!match) return undefined;
	const token = match[1];
	if (
		token === "timeout" ||
		token === "malformed_json" ||
		token === "spawn_failed" ||
		token === "inconsistent_exit" ||
		token === "output_too_large" ||
		token === "unexpected"
	) {
		return token;
	}
	return undefined;
}

/**
 * Transient protocol failures warrant one automatic retry (spawn/JSON glitches).
 * Deterministic `decision: "error"` / unexpected responses do not retry.
 */
export function isTransientProtocolFailure(
	failureClass: ProtocolFailureClass | undefined,
): boolean {
	return (
		failureClass === "timeout" ||
		failureClass === "malformed_json" ||
		failureClass === "spawn_failed" ||
		failureClass === "output_too_large" ||
		failureClass === "inconsistent_exit"
	);
}

/**
 * `allow-with-warning` may soft-allow only true binary unavailability.
 * Protocol corruption / typed decision errors always fail closed (Phase 5).
 */
export function allowWithWarningPermitsProtocolClass(
	failureClass: ProtocolFailureClass | undefined,
): boolean {
	return failureClass === "spawn_failed";
}

type RykEvaluateResponse = {
	decision?: string;
	reason?: string;
	message?: string;
	severity?: string;
	rule_id?: string;
	ruleId?: string;
	pack_id?: string;
	packId?: string;
	pattern_name?: string;
	patternName?: string;
	remediation?: Array<{ description?: string }>;
	error?: { message?: string };
};

export type RykDecisionCard = {
	/** block=deny, ask=needs decision, wait=parent-forward pending */
	variant: "block" | "ask" | "wait";
	title: string;
	summary: string;
	rule?: string;
	pack?: string;
	severity?: string;
	nextStep?: string;
	/** Optional tool/command preview line */
	preview?: string;
	/** For wait cards: timeout hint */
	timeoutHint?: string;
};

type RunProcessResult = {
	code: number | null;
	stdout: string;
	stderr: string;
	error?: Error;
	timedOut?: boolean;
};

type SetupResult = {
	status: "ready" | "missing" | "degraded";
	message: string;
};
/**
 * Sticky recovery after the first protocol-failure dialog in a session.
 * - unset: prompt (or parent-forward) on protocol errors
 * - block: auto-block further protocol errors without re-prompting
 */
export type ProtocolRecovery = "block";

type SessionState = {
	bypass: boolean;
	status: SetupResult["status"];
	bootstrap?: Promise<SetupResult>;
	/** Consecutive decide/evaluate protocol failures (reset on non-error decision). */
	protocolFailures: number;
	/** True after one-shot degraded notify for this session. */
	protocolDegradedNotified: boolean;
	/**
	 * After the user (or parent) chooses session block for protocol failures,
	 * further protocol errors auto-block without another select.
	 */
	protocolRecovery?: ProtocolRecovery;
};

export type RykExtensionOptions = {
	rykBin?: string;
	resolveBin?: () => ResolvedRykBin;
	spawn?: SpawnLike;
	timeoutMs?: number;
	/** Override IPC root (tests). */
	piAskRoot?: string;
	/** Inject fs for parent-ask IPC (tests). */
	piAskFs?: ParentAskFs;
	/** Inject clock for parent-ask wait (tests). */
	now?: () => number;
	/** Inject sleep for parent-ask wait (tests). */
	sleep?: (ms: number) => Promise<void>;
	/** Parent poll interval ms; 0 disables background poll (tests may call poll manually). */
	parentAskPollMs?: number;
};

export type ResolvedRykBin = {
	rykBin: string;
	daemonBin?: string;
	source: "explicit" | "bundled" | "path" | "missing";
};

type ResolveRykBinOptions = {
	env?: NodeJS.ProcessEnv;
	bundledPackageRoot?: string;
	isExecutable?: (path: string) => boolean;
	isPathCompatible?: () => boolean;
	spawnSync?: SpawnSyncLike;
};

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_CHILD_OUTPUT_BYTES = 1024 * 1024;
const REQUIRED_RYK_VERSION = (() => {
	try {
		const deps = (
			createRequire(import.meta.url)("../package.json") as {
				dependencies: Record<string, string>;
			}
		).dependencies;
		return deps["@rykan/ryk"] ?? "1.2.9";
	} catch {
		// The bundled installer deliberately ships only the extension runtime.
		// Its generated wrapper injects the exact ryk binary, so this fallback is
		// used only when package metadata is unavailable.
		return "1.2.9";
	}
})();
// Protocol recovery: session allow first, then once, then sticky block.
const PROTOCOL_SESSION_ALLOW_OPTION = LABEL_PROTOCOL_SESSION_ALLOW;
const PROTOCOL_BLOCK_OPTION = LABEL_DENY;
const ASK_OPTIONS = [
	PROTOCOL_SESSION_ALLOW_OPTION,
	LABEL_ALLOW_ONCE,
	PROTOCOL_BLOCK_OPTION,
] as const;
const POLICY_ASK_OPTIONS = [
	LABEL_ALLOW_ONCE,
	LABEL_DENY,
	SESSION_GRANT_OPTION,
	LABEL_DISABLE_SESSION,
	LABEL_SHOW_WHY,
] as const;
const ONCE_OPTION = LABEL_ALLOW_ONCE;

/**
 * Whether interactive prompts may offer "Allow once".
 * - `RYK_PI_ALLOW_ONCE=false|0|no` disables always
 * - `RYK_PI_MODE=strict` disables by default (production hardening)
 * - `RYK_PI_ALLOW_ONCE=true` re-enables even under strict
 */
export function allowOnceBypassEnabled(
	env: NodeJS.ProcessEnv = process.env,
	unavailableMode?: UnavailableMode,
): boolean {
	const raw = env.RYK_PI_ALLOW_ONCE?.trim().toLowerCase();
	if (raw === "false" || raw === "0" || raw === "no") return false;
	if (raw === "true" || raw === "1" || raw === "yes") return true;
	if (unavailableMode === "strict") return false;
	return true;
}

export function askOptionsFor(
	kind: "policy" | "unavailable",
	allowOnce: boolean,
): string[] {
	const base = kind === "policy" ? [...POLICY_ASK_OPTIONS] : [...ASK_OPTIONS];
	if (allowOnce) return base;
	return base.filter((option) => option !== ONCE_OPTION);
}

/** Sticky protocol-recovery block label. */
export function protocolBlockOptionLabel(): string {
	return PROTOCOL_BLOCK_OPTION;
}

/** Session-wide allow (bypass) label for protocol recovery. */
export function protocolSessionAllowOptionLabel(): string {
	return PROTOCOL_SESSION_ALLOW_OPTION;
}

const DECIDE_EXIT_CODE = {
	allow: 0,
	context_only: 0,
	block: 3,
	ask: 7,
	stage: 7,
	warn: 8,
	error: 1,
} as const;

export function resolveRykBin(
	options: ResolveRykBinOptions = {},
): ResolvedRykBin {
	const env = options.env ?? process.env;
	const isExecutable = options.isExecutable ?? isExecutableFile;
	const explicit = env.RYK_BIN?.trim();
	if (explicit && isExecutable(explicit))
		return { rykBin: explicit, source: "explicit" };

	const packageRoot = options.bundledPackageRoot ?? resolveBundledPackageRoot();
	if (packageRoot) {
		const executableSuffix = process.platform === "win32" ? ".exe" : "";
		const rykBin = resolve(packageRoot, "vendor", `ryk${executableSuffix}`);
		const daemonBin = resolve(
			packageRoot,
			"vendor",
			`ryk-daemon${executableSuffix}`,
		);
		// Bundled ryk vendor only (hard-cut: no ryk vendor dual path). Daemon optional.
		if (isExecutable(rykBin)) {
			return {
				rykBin,
				daemonBin: isExecutable(daemonBin) ? daemonBin : undefined,
				source: "bundled",
			};
		}
	}

	const allowPath = env.RYK_PI_USE_PATH === "true";
	if (allowPath) {
		if (options.isPathCompatible) {
			if (options.isPathCompatible()) {
				return { rykBin: "ryk", source: "path" };
			}
		} else {
			const pathBin = resolveCompatiblePathCli(
				env,
				options.spawnSync ?? spawnSync,
			);
			if (pathBin) return { rykBin: pathBin, source: "path" };
		}
	}

	return { rykBin: "__ryk_bundled_runtime_missing__", source: "missing" };
}

export function buildEvaluateRequest(
	command: string,
	ctx: PiContext,
	toolName = "bash",
): RykEvaluateRequest {
	return {
		schema_version: 1,
		request_id: `pi-${randomUUID()}`,
		kind: "shell_command",
		command,
		cwd: resolveCwd(ctx.cwd),
		source: {
			host: "pi",
			tool_name: toolName,
			mode: ctx.mode,
			session_id: sessionKey(ctx),
		},
	};
}

export function buildDecideFilePayload(
	path: string,
	operation: "read" | "write" = "write",
): RykDecideFileRequest {
	return { path, operation };
}

/** Payload for `ryk decide tool --json` (tool name only; no arg extraction). */
export function buildDecideToolPayload(input: {
	name: string;
}): RykDecideToolRequest {
	return { name: input.name.trim() };
}

export function resolveToolPath(pathInput: string, ctx: PiContext): string {
	const trimmed = pathInput.trim();
	if (!trimmed) return trimmed;
	if (isAbsolute(trimmed)) return resolve(trimmed);
	return resolve(resolveCwd(ctx.cwd), trimmed);
}

async function runRykEvaluateOnce(
	request: RykEvaluateRequest,
	options: Required<
		Pick<RykExtensionOptions, "rykBin" | "spawn" | "timeoutMs">
	> & { env?: NodeJS.ProcessEnv },
): Promise<RykDecision> {
	const result = await runProcess(
		options.rykBin,
		["evaluate", "--json", "--stdin"],
		JSON.stringify(request),
		options.spawn,
		options.timeoutMs,
		options.env,
		request.cwd,
	);

	if (result.timedOut) {
		return {
			kind: "error",
			failureClass: "timeout",
			reason: formatProtocolErrorReason("timeout", "ryk evaluation timed out."),
		};
	}

	if (result.error) {
		const oversized =
			result.error.message === "ryk output exceeded maximum size";
		const failureClass: ProtocolFailureClass = oversized
			? "output_too_large"
			: "spawn_failed";
		const detail = oversized
			? "ryk output exceeded maximum size."
			: "ryk is unavailable.";
		return {
			kind: "error",
			failureClass,
			reason: formatProtocolErrorReason(failureClass, detail),
			error: result.error,
		};
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(result.stdout);
	} catch {
		return {
			kind: "error",
			failureClass: "malformed_json",
			reason: formatProtocolErrorReason(
				"malformed_json",
				formatMalformedJsonDetail(result, "evaluate"),
			),
		};
	}

	const decision = getStringField(parsed, "decision");
	if (decision === "allow" && result.code === 0) {
		return { kind: "allow", response: parsed };
	}
	// Leftover unused ask is remapped by ryk evaluate. Unexpected evaluate
	// ask is fail-closed. SoftBlock/FM/stage arrive as deny/stage and never
	// become allow. Decide-file leftover unused ask is handled in
	// runRykDecideOnce → resolvePolicyAsk (attended permit).
	if (decision === "ask" && (result.code === 0 || result.code === null)) {
		return {
			kind: "deny",
			reason: sanitizeVisibleText(getDecisionReason(parsed)) ||
				"ryk leftover unused ask was not remapped; blocked fail-closed.",
			response: parsed,
		};
	}
	if (decision === "deny") {
		return { kind: "deny", reason: safeRykReason(parsed), response: parsed };
	}
	if (decision === "error") {
		return {
			kind: "error",
			failureClass: "unexpected",
			reason: formatProtocolErrorReason(
				"unexpected",
				sanitizeVisibleText(getDecisionReason(parsed)),
			),
			response: parsed,
		};
	}

	return {
		kind: "error",
		failureClass: "inconsistent_exit",
		reason: formatProtocolErrorReason(
			"inconsistent_exit",
			`ryk returned an unexpected evaluation result (exit ${result.code ?? "unknown"}).`,
		),
		response: parsed,
	};
}

/**
 * Shell evaluate with one automatic retry on *transient* protocol failure.
 * Fail-closed per call; never allows on error. Non-transient errors (e.g.
 * schema-valid decision:"error") are not retried.
 */
export async function runRykEvaluate(
	request: RykEvaluateRequest,
	options: Required<
		Pick<RykExtensionOptions, "rykBin" | "spawn" | "timeoutMs">
	> & { env?: NodeJS.ProcessEnv },
): Promise<RykDecision> {
	const first = await runRykEvaluateOnce(request, options);
	if (first.kind !== "error") return first;
	if (!isTransientProtocolFailure(first.failureClass)) return first;
	return runRykEvaluateOnce(request, options);
}

type DecideRuntimeOptions = Required<
	Pick<RykExtensionOptions, "rykBin" | "spawn" | "timeoutMs">
> & { env?: NodeJS.ProcessEnv; cwd?: string };

/**
 * Single decide attempt. Fail-closed on timeout, spawn error, malformed JSON,
 * and decision/exit-code mismatch. Reasons include a class token for recovery UX.
 */
async function runRykDecideOnce(
	kind: "file" | "tool",
	payload: object,
	options: DecideRuntimeOptions,
	map: {
		defaultReason: string;
		/** File write only: context_only must not allow side effects. */
		denyContextOnly?: boolean;
	},
): Promise<RykDecision> {
	const result = await runProcess(
		options.rykBin,
		["decide", kind, "--json", JSON.stringify(payload)],
		undefined,
		options.spawn,
		options.timeoutMs,
		options.env,
		options.cwd,
	);

	if (result.timedOut) {
		return {
			kind: "error",
			failureClass: "timeout",
			reason: formatProtocolErrorReason("timeout", "ryk decide timed out."),
		};
	}
	if (result.error) {
		const oversized =
			result.error.message === "ryk output exceeded maximum size";
		const failureClass: ProtocolFailureClass = oversized
			? "output_too_large"
			: "spawn_failed";
		const detail = oversized
			? "ryk output exceeded maximum size."
			: "ryk is unavailable.";
		return {
			kind: "error",
			failureClass,
			reason: formatProtocolErrorReason(failureClass, detail),
			error: result.error,
		};
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(result.stdout);
	} catch {
		return {
			kind: "error",
			failureClass: "malformed_json",
			reason: formatProtocolErrorReason(
				"malformed_json",
				formatMalformedJsonDetail(result, "decide"),
			),
		};
	}

	const decision = getStringField(parsed, "decision");
	const reason = sanitizeVisibleText(
		getStringFieldAny(parsed, ["reason", "message"]) ?? map.defaultReason,
	);
	// Trust a machine decision only when process status matches the frozen
	// `ryk decide` exit-code contract. Mismatches fail closed.
	if (
		!decision ||
		!(decision in DECIDE_EXIT_CODE) ||
		result.code !== DECIDE_EXIT_CODE[decision as keyof typeof DECIDE_EXIT_CODE]
	) {
		return {
			kind: "error",
			failureClass: "inconsistent_exit",
			reason: formatProtocolErrorReason(
				"inconsistent_exit",
				`ryk decide returned an inconsistent result (decision ${decision ?? "missing"}, exit ${result.code ?? "signal"}).`,
			),
			response: parsed,
		};
	}

	// decide uses allow | block | ask | warn | context_only | error.
	if (decision === "context_only" && map.denyContextOnly) {
		const response = {
			...(parsed as Record<string, unknown>),
			decision: "deny",
			reason: "ryk allowed context only; write side effects are not permitted.",
		};
		return { kind: "deny", reason: safeRykReason(response), response };
	}
	if (decision === "allow" || decision === "context_only") {
		return { kind: "allow", response: parsed };
	}
	if (decision === "block" || decision === "stage") {
		const normalized = normalizeDecideToEvaluateShape(parsed);
		return {
			kind: "deny",
			reason: safeRykReason(normalized),
			response: normalized,
		};
	}
	if (decision === "ask") {
		return { kind: "ask", reason, response: parsed };
	}
	if (decision === "warn") {
		return { kind: "warn", reason, response: parsed };
	}
	if (decision === "error") {
		return {
			kind: "error",
			failureClass: "unexpected",
			reason: formatProtocolErrorReason("unexpected", reason),
			response: parsed,
		};
	}

	return {
		kind: "error",
		failureClass: "unexpected",
		reason: formatProtocolErrorReason(
			"unexpected",
			`ryk decide returned an unexpected result (exit ${result.code ?? "unknown"}).`,
		),
		response: parsed,
	};
}

/**
 * Shared `ryk decide <kind> --json` runner with one automatic retry on
 * *transient* protocol failure. Fail-closed per call; never allows on error.
 */
async function runRykDecide(
	kind: "file" | "tool",
	payload: object,
	options: DecideRuntimeOptions,
	map: {
		defaultReason: string;
		/** File write only: context_only must not allow side effects. */
		denyContextOnly?: boolean;
	},
): Promise<RykDecision> {
	const first = await runRykDecideOnce(kind, payload, options, map);
	if (first.kind !== "error") return first;
	if (!isTransientProtocolFailure(first.failureClass)) return first;
	return runRykDecideOnce(kind, payload, options, map);
}

/** Non-shell file tools → Zig `ryk decide file` (path only; not daemon Evaluate). */
export async function runRykDecideFile(
	payload: RykDecideFileRequest,
	options: DecideRuntimeOptions,
): Promise<RykDecision> {
	return runRykDecide("file", payload, options, {
		defaultReason: "ryk blocked this file action.",
		denyContextOnly: payload.operation === "write",
	});
}

/**
 * Custom / MCP-shaped tools → Zig `ryk decide tool` (name only).
 * Does not extract paths or args from custom tool inputs.
 */
export async function runRykDecideTool(
	payload: RykDecideToolRequest,
	options: DecideRuntimeOptions,
): Promise<RykDecision> {
	return runRykDecide("tool", payload, options, {
		defaultReason: "ryk blocked this tool action.",
	});
}

function normalizeDecideToEvaluateShape(response: unknown): unknown {
	if (!response || typeof response !== "object") return response;
	const obj = response as Record<string, unknown>;
	return {
		...obj,
		decision:
			obj.decision === "block" || obj.decision === "stage"
				? "deny"
				: obj.decision,
		rule_id: typeof obj.rule === "string" ? obj.rule : obj.rule_id,
	};
}

function blockMalformedToolCall(
	pi: PiAPI,
	ctx: PiContext,
	toolLabel: string,
	summary: string,
): ToolCallResult {
	const details = {
		variant: "block" as const,
		title: DISPLAY_BRAND,
		summary,
	};
	showRykDecision(pi, ctx, details);
	return block(formatAgentBlockReason(details, toolLabel));
}

async function runRykCommand(
	args: string[],
	options: Required<
		Pick<RykExtensionOptions, "rykBin" | "spawn" | "timeoutMs">
	> & { env?: NodeJS.ProcessEnv },
	cwd?: string,
): Promise<RunProcessResult> {
	return runProcess(
		options.rykBin,
		args,
		undefined,
		options.spawn,
		options.timeoutMs,
		options.env,
		cwd,
	);
}

export function resolveUnavailableMode(
	configured: UnavailableMode,
	ctx: PiContext,
): EffectiveUnavailableMode {
	if (configured === "auto")
		return isNoninteractiveSession(ctx) ? "noninteractive-block" : "ask";
	if (configured === "ask" && isNoninteractiveSession(ctx))
		return "noninteractive-block";
	return configured;
}

/**
 * Pi subagent / child-agent sessions (`PI_SUBAGENT_PARENT_SESSION` set).
 * Policy ask uses parent-forward IPC (see parent_ask.ts / ADR-ipc.md), not
 * local ui.select. Timeout / missing parent still fail-closes to deny.
 */
export function isSubagentSession(
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	return parentSessionIdFromEnv(env) !== null;
}

/**
 * True when this session must not present a local policy select:
 * noninteractive print/json/headless, or Pi subagent (parent-forward only).
 * Does not mean "always auto-deny" for subagents — they try parent first.
 */
function envFlagTruthy(raw: string | undefined): boolean {
	if (!raw) return false;
	const value = raw.trim().toLowerCase();
	return value === "1" || value === "true" || value === "yes" || value === "on";
}

/** Residual ask hardens to deny only when the operator set an unattended/CI flag. */
export function isUnattendedEnv(env: NodeJS.ProcessEnv = process.env): boolean {
	return (
		envFlagTruthy(env.RYK_UNATTENDED) ||
		envFlagTruthy(env.RYK_CI) ||
		envFlagTruthy(env.RYK_NONINTERACTIVE) ||
		envFlagTruthy(env.CI)
	);
}

export function shouldAutoDenyPolicyAsk(
	_ctx: PiContext,
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	return isUnattendedEnv(env);
}

/** Local interactive select is only for main TUI sessions. */
export function shouldLocalSelectPolicyAsk(
	ctx: PiContext,
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	return !isNoninteractiveSession(ctx) && !isSubagentSession(env);
}

export function isNoninteractiveSession(ctx: PiContext): boolean {
	return ctx.hasUI !== true || isNoninteractiveMode(ctx.mode);
}

function isNoninteractiveMode(mode: string | undefined): boolean {
	return mode === "print" || mode === "json" || mode === "noninteractive";
}

function policyAskAutoDenyClass(
	env: NodeJS.ProcessEnv,
): "subagent" | "non-interactive" {
	if (isSubagentSession(env)) return "subagent";
	return "non-interactive";
}

export function safeRykReason(response: unknown): string {
	return formatRykDecisionSummary(buildRykDecisionCard(response, "block"));
}

/** Prefer one short agent-facing block line (Why + rule + one Next when known). */
const AGENT_BLOCK_REASON_MAX = 320;
const AGENT_NEXT_CLAUSE_MAX = 120;

/**
 * Agent-facing tool block `reason`: one line, operator walls stripped, optional
 * structured Next from card.nextStep (never invented). Prefer this for policy /
 * protocol agent block text (hardcoded audit-fail strings may stay as-is).
 *
 * Truncation is suffix-first: reserve Next then meta (rule/pack/severity), then
 * clip only the Why atom so a long reason does not drop the rule.
 */
export function formatAgentBlockReason(
	card: RykDecisionCard,
	toolLabel = "bash",
): string {
	const why = stripOperatorWalls(card.summary);
	const action = toolLabel === "bash" ? "bash command" : `${toolLabel} action`;
	const verb =
		card.variant === "ask" || card.variant === "wait"
			? "needs your decision"
			: `blocked this ${action}`;
	const prefix = `${PRODUCT_NAME} ${verb}: `;

	const metaParts: string[] = [];
	if (card.rule) metaParts.push(`rule ${card.rule}`);
	if (card.pack && card.pack !== card.rule?.split(":")[0])
		metaParts.push(`pack ${card.pack}`);
	if (card.severity) metaParts.push(`severity ${card.severity}`);
	const metaSuffix = metaParts.length ? ` • ${metaParts.join(" • ")}` : "";

	const nextRaw = card.nextStep?.trim();
	const nextClause = nextRaw
		? truncate(sanitizeVisibleText(nextRaw), AGENT_NEXT_CLAUSE_MAX)
		: "";
	const nextSuffix = nextClause ? ` • Next: ${nextClause}` : "";

	const fixedTail = `${metaSuffix}${nextSuffix}`;
	const whyBudget = Math.max(
		24,
		AGENT_BLOCK_REASON_MAX - prefix.length - fixedTail.length,
	);
	let reason = sanitizeVisibleText(
		`${prefix}${truncate(why, whyBudget)}${fixedTail}`,
	);
	// Defense in depth: strip residual Recourse walls without eating rule/Next bullets.
	if (/Recourse:/i.test(reason)) {
		reason = sanitizeVisibleText(
			reason.replace(/\s*Recourse:\s*[^•]*?(?=\s*•|$)/gi, ""),
		);
	}
	return truncate(reason, AGENT_BLOCK_REASON_MAX);
}

/** Pi requires `{ render(width) => string[] }`; a string is truthy and crashes the TUI. */
export type TuiComponentLike = {
	render: (width: number) => string[];
};

export function tuiTextComponent(text: string): TuiComponentLike {
	return {
		render(_width: number): string[] {
			if (text.length === 0) return [""];
			return text.split("\n");
		},
	};
}

export function decisionStatusLabel(
	variant: RykDecisionCard["variant"],
): string {
	if (variant === "ask") return "Needs approval";
	if (variant === "wait") return "Waiting";
	return "Blocked";
}

export function decisionTone(
	variant: RykDecisionCard["variant"],
): "error" | "warning" | "dim" {
	if (variant === "ask") return "warning";
	if (variant === "wait") return "dim";
	return "error";
}

const PLAIN_THEME: PiTheme = {
	fg: (_name, text) => text,
};

/**
 * Themed decision lines for the Pi transcript renderer.
 * Hierarchy: brand+status → Why/Cmd → Meta → Next. No box-drawing.
 */
export function buildThemedDecisionLines(
	card: RykDecisionCard,
	theme: PiTheme,
): string[] {
	const tone = decisionTone(card.variant);
	const status = decisionStatusLabel(card.variant);
	const brand = theme.bold ? theme.bold(DISPLAY_BRAND) : DISPLAY_BRAND;
	const header = `${theme.fg(tone, brand)} ${theme.fg("dim", `· ${status}`)}`;
	const lines: string[] = [header, ""];
	const contentWidth = Math.min(
		72,
		Math.max(48, Math.min(terminalContentWidth(), 72)),
	);

	for (const row of decisionCardRows(card)) {
		lines.push(
			...formatMinimalRow(row.label, row.value, contentWidth, (lab, val, first) => {
				const labelPart = theme.fg("dim", lab);
				if (!first) return `${lab}${val}`;
				if (row.label === "Cmd") {
					return `${labelPart}${theme.fg("dim", val)}`;
				}
				return `${labelPart}${val}`;
			}),
		);
	}
	return lines;
}

function renderDecisionMessage(
	message: { content?: string; details?: unknown },
	_options: { expanded?: boolean; outputPad?: number },
	theme: PiTheme,
): TuiComponentLike {
	const details = message.details as RykDecisionCard | undefined;
	const card: RykDecisionCard = details ?? {
		variant: "block",
		title: DISPLAY_BRAND,
		summary:
			typeof message.content === "string" && message.content.length > 0
				? message.content
				: "Decision",
	};
	return tuiTextComponent(buildThemedDecisionLines(card, theme).join("\n"));
}

export function installRykExtension(
	pi: PiAPI,
	extensionOptions: RykExtensionOptions = {},
): void {
	// Prefer theme tokens over purple default / ASCII frames. Always return
	// `{ render(width) }` — a string crashes Pi with child.render is not a function.
	try {
		pi.registerMessageRenderer?.(DECISION_CUSTOM_TYPE, renderDecisionMessage);
	} catch {
		// Older hosts without registerMessageRenderer — plain text content still works.
	}

	const resolvedBin = extensionOptions.rykBin
		? { rykBin: extensionOptions.rykBin, source: "explicit" as const }
		: (extensionOptions.resolveBin ?? resolveRykBin)();
	const runtime = {
		rykBin: resolvedBin.rykBin,
		spawn: extensionOptions.spawn ?? (nodeSpawn as unknown as SpawnLike),
		timeoutMs:
			extensionOptions.timeoutMs ??
			Number(
				process.env.RYK_PI_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS,
			),
		env: resolvedBin.daemonBin
			? { ...process.env, RYK_DAEMON: resolvedBin.daemonBin }
			: process.env,
	};

	const askFs = extensionOptions.piAskFs;
	const askRoot =
		extensionOptions.piAskRoot ?? resolvePiAskRoot(runtime.env, askFs);
	const askNow = extensionOptions.now ?? Date.now;
	const askSleep =
		extensionOptions.sleep ??
		((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
	const parentPollMs =
		extensionOptions.parentAskPollMs === undefined
			? 1_000
			: extensionOptions.parentAskPollMs;
	let parentPollTimer: ReturnType<typeof setInterval> | undefined;
	let parentPollBusy = false;

	let unavailableMode: UnavailableMode =
		parseMode(process.env.RYK_PI_MODE) ?? "auto";
	const sessionState = new Map<string, SessionState>();

	const stateFor = (ctx: PiContext): SessionState => {
		const key = sessionKey(ctx);
		const current = sessionState.get(key);
		if (current) return current;
		const next: SessionState = {
			bypass: false,
			status: "degraded",
			protocolFailures: 0,
			protocolDegradedNotified: false,
		};
		sessionState.set(key, next);
		return next;
	};

	const updateStatus = (ctx: PiContext): void => {
		if (stateFor(ctx).bypass) {
			ctx.ui?.setStatus?.(STATUS_KEY, "rykan v bypass");
			return;
		}
		ctx.ui?.setStatus?.(STATUS_KEY, `rykan v ${stateFor(ctx).status}`);
	};

	const grantsDirFor = (sessionId: string) =>
		parentAskDir(askRoot, sessionId, askFs);

	const checkSessionGrant = (
		toolName: string,
		env: NodeJS.ProcessEnv,
		ctx: PiContext,
	): boolean => {
		const parentId = parentSessionIdFromEnv(env);
		const localId = ctx.sessionManager?.getSessionId?.()?.trim();
		const ids = [parentId, localId].filter(
			(id): id is string => typeof id === "string" && id.length > 0,
		);
		for (const id of ids) {
			if (hasSessionGrant(grantsDirFor(id), toolName, askFs)) return true;
		}
		return false;
	};

	const recordSessionGrantHit = (toolLabel: string): void => {
		if (!pi.sendMessage) return;
		try {
			pi.sendMessage(
				{
					customType: "ryk.audit",
					content: `ryk session grant hit: ${toolLabel}`,
					display: false,
					details: {
						event: "ryk_session_grant_hit",
						tool: truncate(sanitizeVisibleText(toolLabel), 128),
					},
				},
				{ triggerTurn: false },
			);
		} catch {
			// allow still proceeds; grant is explicit session approval
		}
	};

	/**
	 * Parent main session: drain pending child ask requests via local select.
	 * Exported behavior for tests via returned poll closure is not public API;
	 * tests drive via tool_call hooks + injected fs.
	 */
	const pollParentAsks = async (ctx: PiContext): Promise<void> => {
		if (isSubagentSession(runtime.env)) return;
		if (isNoninteractiveSession(ctx)) return;
		if (parentPollBusy) return;
		const sessionId = ctx.sessionManager?.getSessionId?.()?.trim();
		if (!sessionId) return;
		parentPollBusy = true;
		try {
			const dir = grantsDirFor(sessionId);
			const pending = listPendingRequests(dir, askFs);
			for (const req of pending) {
				if (
					sanitizeSessionId(req.parent_session) !== sanitizeSessionId(sessionId)
				) {
					continue;
				}
				await answerParentAskRequest(req, dir, pi, ctx, {
					allowOnce: allowOnceBypassEnabled(runtime.env, unavailableMode),
					disableSession: () => {
						stateFor(ctx).bypass = true;
						updateStatus(ctx);
					},
					now: askNow,
					fsApi: askFs,
				});
			}
		} finally {
			parentPollBusy = false;
		}
	};

	const startParentPoll = (ctx: PiContext): void => {
		if (parentPollMs <= 0) return;
		if (isSubagentSession(runtime.env)) return;
		if (parentPollTimer) return;
		parentPollTimer = setInterval(() => {
			void pollParentAsks(ctx);
		}, parentPollMs);
		// unref so Node can exit if only the timer remains
		parentPollTimer.unref?.();
	};

	const stopParentPoll = (): void => {
		if (parentPollTimer) {
			clearInterval(parentPollTimer);
			parentPollTimer = undefined;
		}
	};

	pi.on("session_start", (_event, ctx) => {
		const state = stateFor(ctx);
		state.bypass = false;
		state.status = "degraded";
		state.protocolFailures = 0;
		state.protocolDegradedNotified = false;
		updateStatus(ctx);
		startParentPoll(ctx);
		void pollParentAsks(ctx);
		if (
			process.env.RYK_PI_AUTO_SETUP === "false"
		) {
			state.status = "ready";
			updateStatus(ctx);
			return;
		}
		state.bootstrap = setupRyk(ctx, runtime);
		void state.bootstrap.then((result) => {
			state.status = result.status;
			updateStatus(ctx);
		});
	});

	pi.on("session_shutdown", (_event, ctx) => {
		stateFor(ctx).bypass = false;
		ctx.ui?.setStatus?.(STATUS_KEY, undefined);
		clearRykWidget(ctx);
		stopParentPoll();
		// Grants die with parent session.
		if (!isSubagentSession(runtime.env)) {
			const sessionId = ctx.sessionManager?.getSessionId?.()?.trim();
			if (sessionId) cleanupParentAskDir(grantsDirFor(sessionId), askFs);
		}
	});

	// Credential capture from prompt (Pi only). Still runs when bash bypass is on
	// so secrets are not forwarded to the model by default.
	pi.on("input", async (event, ctx: PiContext) => {
		if (isSecretCaptureDisabled()) return { action: "continue" as const };
		return handleSecretCaptureInput(
			{
				text: typeof event?.text === "string" ? event.text : "",
				source: typeof event?.source === "string" ? event.source : undefined,
				images: event?.images,
			},
			ctx,
		);
	});

	// Defense in depth: scrub any secret-like spans still present in user messages
	// before the LLM call (no consent/store prompts on history).
	pi.on("context", async (event) => {
		if (isSecretCaptureDisabled()) return undefined;
		const messages = event?.messages;
		if (!Array.isArray(messages)) return undefined;
		const scrubbed = scrubContextMessages(
			messages as Array<Record<string, unknown>>,
		);
		return { messages: scrubbed };
	});

	pi.on(
		"tool_call",
		async (event: PiToolCallEvent, ctx: PiContext): Promise<ToolCallResult> => {
			await stateFor(ctx).bootstrap;

			// Drain pending child asks while parent is active (also helps tests
			// without relying solely on the background interval).
			if (!isSubagentSession(runtime.env)) {
				await pollParentAsks(ctx);
			}

			if (stateFor(ctx).bypass) {
				clearRykWidget(ctx);
				ctx.ui?.notify?.(
					`ryk protection is disabled for this Pi session; ${event.toolName} allowed without ryk evaluation.`,
					"warning",
				);
				updateStatus(ctx);
				return undefined;
			}

			const toolLabel = event.toolName;
			const disableSession = () => {
				stateFor(ctx).bypass = true;
				updateStatus(ctx);
			};

			// Session grant short-circuit (parent or local session allowlist).
			if (checkSessionGrant(toolLabel, runtime.env, ctx)) {
				recordSessionGrantHit(toolLabel);
				clearRykWidget(ctx);
				return undefined;
			}

			if (event.toolName === "bash") {
				if (
					typeof event.input?.command !== "string" ||
					event.input.command.trim().length === 0
				) {
					return blockMalformedToolCall(
						pi,
						ctx,
						toolLabel,
						"malformed Pi bash tool call; missing non-empty command.",
					);
				}
				const decision = await runRykEvaluate(
					buildEvaluateRequest(event.input.command, ctx, "bash"),
					runtime,
				);
				return applyToolDecision(
					decision,
					pi,
					ctx,
					toolLabel,
					unavailableMode,
					disableSession,
					runtime.env,
					stateFor(ctx),
					{
						askRoot,
						askFs,
						askNow,
						askSleep,
						commandOrName:
							typeof event.input?.command === "string"
								? event.input.command
								: toolLabel,
					},
				);
			}

			// write/edit → decide file write; read/grep/find/ls → decide file read
			if (isProtectedPiTool(event.toolName)) {
				const pathTarget = extractDecideFilePath(event.toolName, event.input);
				if (!pathTarget) return undefined;
				if (pathTarget.required && !pathTarget.path) {
					return blockMalformedToolCall(
						pi,
						ctx,
						toolLabel,
						`malformed Pi ${toolLabel} tool call; missing non-empty path.`,
					);
				}
				const absPath = resolveToolPath(pathTarget.path, ctx);
				const operation: "read" | "write" = FILE_WRITE_TOOLS.has(event.toolName)
					? "write"
					: "read";
				const decision = await runRykDecideFile(
					buildDecideFilePayload(absPath, operation),
					{ ...runtime, cwd: resolveCwd(ctx.cwd) },
				);
				if (
					decision.kind === "allow" &&
					BROAD_DISCOVERY_TOOLS.has(event.toolName)
				) {
					// Root already passed decide-file. Leftover unused ask is
					// remapped by ryk; do not invent a second host approval gate.
					return undefined;
				}
				return applyToolDecision(
					decision,
					pi,
					ctx,
					toolLabel,
					unavailableMode,
					disableSession,
					runtime.env,
					stateFor(ctx),
					{
						askRoot,
						askFs,
						askNow,
						askSleep,
						commandOrName: absPath,
					},
				);
			}

			// Custom / MCP-shaped tools → name-gated decide tool (not full MCP proxy).
			// Pi control-plane tools (contact_supervisor, intercom, subagent) pass through.
			const name = (event.toolName ?? "").trim();
			if (!name) {
				return blockMalformedToolCall(
					pi,
					ctx,
					"tool",
					"malformed Pi tool call; missing non-empty tool name.",
				);
			}
			if (!shouldNameGateTool(name)) {
				clearRykWidget(ctx);
				return undefined;
			}
			const decision = await runRykDecideTool(
				buildDecideToolPayload({ name }),
				{ ...runtime, cwd: resolveCwd(ctx.cwd) },
			);
			return applyToolDecision(
				decision,
				pi,
				ctx,
				toolLabel,
				unavailableMode,
				disableSession,
				runtime.env,
				stateFor(ctx),
				{
					askRoot,
					askFs,
					askNow,
					askSleep,
					commandOrName: name,
				},
			);
		},
	);

	const setupHandler = async (
		_args: string | undefined,
		ctx: PiContext,
	): Promise<void> => {
		const result = await setupRyk(ctx, runtime);
		stateFor(ctx).status = result.status;
		updateStatus(ctx);
		notify(
			ctx,
			result.message,
			result.status === "ready"
				? "info"
				: result.status === "missing"
					? "error"
					: "warning",
		);
	};

	const startHandler = async (_args: string | undefined, ctx: PiContext) => {
		stateFor(ctx).bypass = false;
		const result = await setupRyk(ctx, runtime);
		stateFor(ctx).status = result.status;
		updateStatus(ctx);
		const suffix =
			result.status === "ready"
				? "ryk protection is enabled for this Pi session."
				: result.message;
		const type =
			result.status === "ready"
				? "info"
				: result.status === "missing"
					? "error"
					: "warning";
		notify(ctx, suffix, type);
	};

	const stopHandler = (_args: string | undefined, ctx: PiContext) => {
		stateFor(ctx).bypass = true;
		updateStatus(ctx);
		notify(
			ctx,
			`ryk disabled for this Pi session only. Protected tools (${piCoverageLabel()}) run without ryk until /ryk-start.`,
			"warning",
		);
	};

	const doctorHandler = async (_args: string | undefined, ctx: PiContext) => {
		const result = await runRykCommand(["doctor"], runtime);
		if (result.error) {
			notify(
				ctx,
				`${rykInstallMessage()}\n\nCoverage: ${piCoverageLabel()}`,
				"error",
			);
			return;
		}
		const body =
			summarizeCommandOutput(result) ||
			`ryk doctor exited with ${result.code ?? "unknown"}`;
		notify(
			ctx,
			`${body}\n\nCoverage: ${piCoverageLabel()}`,
			result.code === 0 ? "info" : "warning",
		);
	};

	// Hard-cut: ryk-* slash commands only (no ryk-* dual registration).
	pi.registerCommand("ryk-setup", {
		description:
			"Ensure the workspace policy exists and probe ryk CLI health.",
		handler: setupHandler,
	});
	pi.registerCommand("ryk-start", {
		description:
			"Re-enable ryk protection for this Pi session and verify setup.",
		handler: startHandler,
	});
	pi.registerCommand("ryk-stop", {
		description:
			"Disable ryk protection for this Pi session until /ryk-start.",
		handler: stopHandler,
	});
	pi.registerCommand("ryk-doctor", {
		 description: "Run ryk doctor and show setup or health diagnostics.",
		handler: doctorHandler,
	});

	const modeHandler = async (args: string | undefined, ctx: PiContext) => {
		const requested = args?.trim().toLowerCase();
		if (!requested) {
			notify(ctx, modeSummary(unavailableMode, stateFor(ctx).bypass), "info");
			return;
		}

		if (requested === "bypass on") {
			stateFor(ctx).bypass = true;
			updateStatus(ctx);
			notify(ctx, "ryk bypass enabled for this Pi session only.", "warning");
			return;
		}
		if (requested === "bypass off") {
			stateFor(ctx).bypass = false;
			updateStatus(ctx);
			notify(
				ctx,
				`ryk bypass disabled. Protected tools (${piCoverageLabel()}) will be evaluated by ryk.`,
				"info",
			);
			return;
		}

		const nextMode = parseMode(requested);
		if (!nextMode) {
			notify(
				ctx,
				"Usage: /ryk-mode [auto|ask|noninteractive-block|strict|allow-with-warning|bypass on|bypass off]",
				"warning",
			);
			return;
		}
		unavailableMode = nextMode;
		updateStatus(ctx);
		notify(ctx, modeSummary(unavailableMode, stateFor(ctx).bypass), "info");
	};

	const pendingHandler = async (_args: string | undefined, ctx: PiContext) => {
		if (isSubagentSession(runtime.env)) {
			notify(ctx, `${PRODUCT_NAME}: run /ryk-pending in the parent (main) Pi session.`, "warning");
			return;
		}
		const sessionId = ctx.sessionManager?.getSessionId?.()?.trim();
		if (!sessionId) {
			notify(ctx, `${PRODUCT_NAME}: no session id — cannot list pending asks.`, "warning");
			return;
		}
		const dir = grantsDirFor(sessionId);
		const pending = listPendingRequests(dir, askFs);
		if (pending.length === 0) {
			notify(ctx, `${PRODUCT_NAME}: no pending subagent asks.`, "info");
			return;
		}
		notify(
			ctx,
			`${PRODUCT_NAME}: ${pending.length} pending subagent ask(s). Opening prompts…`,
			"warning",
		);
		await pollParentAsks(ctx);
	};
	pi.registerCommand("ryk-pending", {
		description: "Drain pending subagent approval requests in this parent session.",
		handler: pendingHandler,
	});

	pi.registerCommand("ryk-mode", {
		description: "View or change ryk Pi unavailable-mode and session bypass.",
		handler: modeHandler,
	});
}

type AskIpcContext = {
	askRoot: string;
	askFs?: ParentAskFs;
	askNow: () => number;
	askSleep: (ms: number) => Promise<void>;
	commandOrName: string;
};

async function applyToolDecision(
	decision: RykDecision,
	pi: PiAPI,
	ctx: PiContext,
	toolLabel: string,
	unavailableMode: UnavailableMode,
	disableSession: () => void,
	env: NodeJS.ProcessEnv = process.env,
	session?: SessionState,
	askIpc?: AskIpcContext,
): Promise<ToolCallResult> {
	if (decision.kind === "allow") {
		if (session) session.protocolFailures = 0;
		clearRykWidget(ctx);
		return undefined;
	}
	if (decision.kind === "deny") {
		if (session) session.protocolFailures = 0;
		const card = buildRykDecisionCard(decision.response, "block");
		const previewSource = askIpc?.commandOrName;
		if (
			previewSource &&
			previewSource !== toolLabel &&
			previewSource.trim().length > 0
		) {
			card.preview = truncate(sanitizeVisibleText(previewSource), 96);
		}
		showRykDecision(pi, ctx, card);
		// Agent reason: short + structured Next; walls stripped.
		const agentReason = formatAgentBlockReason(card, toolLabel);
		// Best-effort error flash; card remains primary. Never softens deny.
		// Strip Recourse/Next on the reason atom so rule/pack/severity suffix survives.
		// Flash stays shorter than agent reason (no Next clause required).
		const flash = formatRykDecisionSummary(
			{ ...card, summary: stripOperatorWalls(card.summary) },
			toolLabel,
		);
		notify(ctx, flash, "error");
		return block(agentReason);
	}
	if (decision.kind === "warn") {
		if (session) session.protocolFailures = 0;
		clearRykWidget(ctx);
		notify(
			ctx,
			`ryk flagged this ${toolLabel} action: ${decision.reason}. Proceeding with warning.`,
			"warning",
		);
		return undefined;
	}
	if (decision.kind === "ask") {
		if (session) session.protocolFailures = 0;
		return resolvePolicyAsk(
			decision.reason,
			pi,
			ctx,
			toolLabel,
			{ disableSession },
			allowOnceBypassEnabled(env, unavailableMode),
			env,
			askIpc,
		);
	}
	// Protocol / unavailable: track consecutive failures; never silent-allow.
	if (session) {
		session.protocolFailures += 1;
		if (
			session.protocolFailures >= PROTOCOL_DEGRADED_THRESHOLD &&
			!session.protocolDegradedNotified
		) {
			session.protocolDegradedNotified = true;
			notify(
				ctx,
				`ryk protocol degraded after ${session.protocolFailures} consecutive evaluation failures. Session recovery applies until /ryk-start or restart. Run /ryk-doctor.`,
				"warning",
			);
		}
	}
	return handleUnavailable(
		decision.reason,
		pi,
		ctx,
		resolveUnavailableMode(unavailableMode, ctx),
		{ disableSession },
		toolLabel,
		allowOnceBypassEnabled(env, unavailableMode),
		session,
		env,
		askIpc,
	);
}

/**
 * Leftover unused policy ask on the plugin wire:
 * - hook/evaluate remaps leftover unused ask to allow first
 * - `ryk decide` still emits leftover unused ask — permit on attended Pi
 * Staged writes, FM steward ask, SoftBlock, and explicit deny never become allow.
 * Unattended (`CI` / `RYK_CI` / `RYK_NONINTERACTIVE` / `RYK_UNATTENDED`) still denies.
 */
async function resolvePolicyAsk(
	reason: string,
	pi: PiAPI,
	ctx: PiContext,
	toolLabel: string,
	_actions: { disableSession: () => void },
	_allowOnce: boolean,
	env: NodeJS.ProcessEnv = process.env,
	_askIpc?: AskIpcContext,
): Promise<ToolCallResult> {
	if (isUnattendedEnv(env)) {
		return handlePolicyAskAutoDeny(reason, pi, ctx, toolLabel, env);
	}
	return undefined;
}

function recordOnceBypass(
	pi: PiAPI,
	ctx: PiContext,
	toolLabel: string,
	source: "policy" | "unavailable",
): boolean {
	if (!pi.sendMessage) {
		notify(
			ctx,
			"ryk blocked the once-bypass because transcript auditing is unavailable.",
			"error",
		);
		return false;
	}
	const details = {
		event: "ryk_once_bypass",
		tool: truncate(sanitizeVisibleText(toolLabel), 128),
		source,
	};
	try {
		pi.sendMessage(
			{
				customType: "ryk.audit",
				content: `ryk once-bypass: ${details.tool} (${source})`,
				display: false,
				details,
			},
			{ triggerTurn: false },
		);
	} catch {
		notify(
			ctx,
			"ryk blocked the once-bypass because transcript auditing failed.",
			"error",
		);
		return false;
	}
	notify(
		ctx,
		`ryk audit: once-bypass used for ${details.tool} (${source}).`,
		"warning",
	);
	return true;
}

/**
 * Best-effort audit for policy ask auto-deny. Deny does not require audit
 * success (unlike once-bypass allow); always block either way.
 */
function recordAskAutoDeny(
	pi: PiAPI,
	toolLabel: string,
	sessionClass: "subagent" | "non-interactive",
	reason: string,
): void {
	if (!pi.sendMessage) return;
	const details = {
		event: "ryk_ask_auto_deny",
		tool: truncate(sanitizeVisibleText(toolLabel), 128),
		session_class: sessionClass,
		reason: truncate(sanitizeVisibleText(reason), 256),
	};
	try {
		pi.sendMessage(
			{
				customType: "ryk.audit",
				content: `ryk ask auto-deny: ${details.tool} (${sessionClass})`,
				display: false,
				details,
			},
			{ triggerTurn: false },
		);
	} catch {
		// Deny is fail-closed regardless of audit success.
	}
}

async function handlePolicyAskAutoDeny(
	reason: string,
	pi: PiAPI,
	ctx: PiContext,
	toolLabel: string,
	env: NodeJS.ProcessEnv = process.env,
	opts?: { rule?: string; sessionClass?: "subagent" | "non-interactive" },
): Promise<ToolCallResult> {
	const sessionClass = opts?.sessionClass ?? policyAskAutoDenyClass(env);
	const policyReason = sanitizeVisibleText(reason);
	const copy = buildAutoDenyCopy(sessionClass, policyReason, toolLabel, {
		rule: opts?.rule,
	});
	const card: RykDecisionCard = {
		variant: "block",
		title: copy.title,
		summary: copy.summary,
		rule: copy.rule,
		nextStep: copy.nextStep,
	};
	// Prefer recording audit before returning the block; still block if audit fails.
	recordAskAutoDeny(pi, toolLabel, sessionClass, policyReason);
	showRykDecision(pi, ctx, card);
	// Agent Why atom keeps "auto-denied" for search, without a second product brand
	// (formatAgentBlockReason already prefixes PRODUCT_NAME + blocked verb).
	return block(
		formatAgentBlockReason(
			{
				...card,
				summary: `auto-denied (${sessionClass}): ${policyReason || `${toolLabel} requires approval`}`,
			},
			toolLabel,
		),
	);
}

/**
 * Child subagent path: write AskRequest, wait for parent res-*.json, apply choice.
 * Timeout / abort / missing parent → fail closed with subagent Why/Next copy.
 */
async function handlePolicyAskParentForward(
	reason: string,
	pi: PiAPI,
	ctx: PiContext,
	toolLabel: string,
	actions: { disableSession: () => void },
	allowOnce: boolean,
	env: NodeJS.ProcessEnv,
	askIpc?: AskIpcContext,
): Promise<ToolCallResult> {
	const parentSession = parentSessionIdFromEnv(env);
	if (!parentSession) {
		return handlePolicyAskAutoDeny(reason, pi, ctx, toolLabel, env, {
			sessionClass: "subagent",
			rule: "rykanv:ask-no-ui",
		});
	}

	const root = askIpc?.askRoot ?? resolvePiAskRoot(env, askIpc?.askFs);
	const fsApi = askIpc?.askFs;
	const now = askIpc?.askNow ?? Date.now;
	const sleep =
		askIpc?.askSleep ??
		((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
	const timeoutMs = parentAskTimeoutMs(env);
	const id = randomUUID();
	const dir = parentAskDir(root, parentSession, fsApi);
	const request: ParentAskRequest = {
		v: 1,
		id,
		parent_session: parentSession,
		child_session: ctx.sessionManager?.getSessionId?.(),
		tool: toolLabel,
		reason: sanitizeVisibleText(reason),
		command_or_name: askIpc?.commandOrName ?? toolLabel,
		created_at_ms: now(),
		timeout_ms: timeoutMs,
	};

	try {
		writeAskRequest(dir, request, fsApi);
	} catch {
		return handlePolicyAskAutoDeny(reason, pi, ctx, toolLabel, env, {
			sessionClass: "subagent",
			rule: "rykanv:parent-ask-timeout",
		});
	}

	const card = buildRykWaitCard({
		toolLabel,
		reason: sanitizeVisibleText(reason),
		commandOrName: askIpc?.commandOrName ?? toolLabel,
		timeoutMs,
	});
	showRykWidget(ctx, card);
	notify(
		ctx,
		`${PRODUCT_NAME}: waiting for approval in the parent Pi session (${toolLabel}).`,
		"info",
	);

	const response = await waitForAskResponse(dir, id, {
		timeoutMs,
		signal: ctx.signal,
		now,
		sleep,
		fsApi,
	});

	clearRykWidget(ctx);

	if (!response) {
		return handlePolicyAskAutoDeny(reason, pi, ctx, toolLabel, env, {
			sessionClass: "subagent",
			rule: "rykanv:parent-ask-timeout",
		});
	}

	return applyParentAskChoice(
		response.choice,
		reason,
		pi,
		ctx,
		toolLabel,
		actions,
		allowOnce,
		env,
		{ parentSession, askRoot: root, askFs: fsApi, askNow: now },
	);
}

async function applyParentAskChoice(
	choice: ParentAskChoice,
	reason: string,
	pi: PiAPI,
	ctx: PiContext,
	toolLabel: string,
	actions: { disableSession: () => void },
	allowOnce: boolean,
	_env: NodeJS.ProcessEnv,
	grantCtx?: {
		parentSession: string;
		askRoot: string;
		askFs?: ParentAskFs;
		askNow: () => number;
	},
): Promise<ToolCallResult> {
	const summary = sanitizeVisibleText(reason);
	switch (choice) {
		case "run_once":
			if (!allowOnce) {
				return block(
					formatAgentBlockReason(
						{ variant: "block", title: DISPLAY_BRAND, summary },
						toolLabel,
					),
				);
			}
			if (!recordOnceBypass(pi, ctx, toolLabel, "policy")) {
				return block(
					"ryk blocked this once-bypass because a required transcript audit event could not be recorded.",
				);
			}
			notify(
				ctx,
				`Parent allowed this ${toolLabel} action once without ryk evaluation.`,
				"warning",
			);
			return undefined;
		case "allow_session_tool":
			if (grantCtx) {
				addSessionGrant(
					parentAskDir(
						grantCtx.askRoot,
						grantCtx.parentSession,
						grantCtx.askFs,
					),
					toolLabel,
					grantCtx.askNow(),
					grantCtx.askFs,
				);
			}
			notify(
				ctx,
				`Parent allowed ${toolLabel} for this Pi session (session grant).`,
				"warning",
			);
			return undefined;
		case "disable_session":
			actions.disableSession();
			notify(
				ctx,
				`${PRODUCT_NAME} disabled for this session only. Use /ryk-start to re-enable.`,
				"warning",
			);
			return undefined;
		case "show_reason":
			notify(ctx, summary, "error");
			return block(
				formatAgentBlockReason(
					{ variant: "block", title: DISPLAY_BRAND, summary },
					toolLabel,
				),
			);
		case "block":
		default:
			return block(
				formatAgentBlockReason(
					{ variant: "block", title: DISPLAY_BRAND, summary },
					toolLabel,
				),
			);
	}
}

/**
 * Parent side: present select for a child request and write AskResponse.
 */
async function answerParentAskRequest(
	req: ParentAskRequest,
	dir: string,
	pi: PiAPI,
	ctx: PiContext,
	options: {
		allowOnce: boolean;
		disableSession: () => void;
		now: () => number;
		fsApi?: ParentAskFs;
	},
): Promise<void> {
	const summary = sanitizeVisibleText(
		`[subagent ask] ${req.tool}: ${req.reason || req.command_or_name}`,
	);
	const preview = truncate(
		sanitizeVisibleText(req.command_or_name || req.tool),
		96,
	);
	const card: RykDecisionCard = {
		...buildRykAskCard(summary),
		preview,
		rule: "rykanv:parent-ask",
	};
	showRykWidget(ctx, card);
	// Surface in status so parent cannot miss a child ask while scrolling.
	ctx.ui?.setStatus?.(STATUS_KEY, "rykan v ask");
	notify(
		ctx,
		`${PRODUCT_NAME}: subagent needs approval for ${req.tool} — answer the prompt.`,
		"warning",
	);
	const choiceLabel = await ctx.ui?.select?.(
		`${PRODUCT_NAME}: subagent · ${req.tool}`,
		askOptionsFor("policy", options.allowOnce),
		{ timeout: Math.max(req.timeout_ms, 5_000), signal: ctx.signal },
	);
	clearRykWidget(ctx);
	const choice = mapSelectLabelToChoice(choiceLabel);

	if (choice === "allow_session_tool") {
		addSessionGrant(dir, req.tool, options.now(), options.fsApi);
	}
	if (choice === "disable_session") {
		options.disableSession();
	}

	writeAskResponse(
		dir,
		{
			v: 1,
			id: req.id,
			choice,
			decided_at_ms: options.now(),
		},
		options.fsApi,
	);

	if (pi.sendMessage) {
		try {
			pi.sendMessage(
				{
					customType: "ryk.audit",
					content: `ryk parent ask response: ${req.tool} → ${choice}`,
					display: false,
					details: {
						event: "ryk_parent_ask_response",
						tool: truncate(sanitizeVisibleText(req.tool), 128),
						choice,
						request_id: req.id,
					},
				},
				{ triggerTurn: false },
			);
		} catch {
			// response already written
		}
	}

	if (choice === "show_reason") {
		notify(ctx, summary, "error");
	} else if (choice === "block" || choiceLabel === undefined) {
		notify(ctx, `Blocked subagent ${req.tool} request.`, "warning");
	} else {
		notify(ctx, `Answered subagent ${req.tool}: ${choice}`, "info");
	}
}

async function handlePolicyAsk(
	reason: string,
	pi: PiAPI,
	ctx: PiContext,
	toolLabel: string,
	actions: { disableSession: () => void },
	allowOnce: boolean,
	env: NodeJS.ProcessEnv = process.env,
	askIpc?: AskIpcContext,
): Promise<ToolCallResult> {
	const summary = sanitizeVisibleText(reason);
	const card = buildRykAskCard(summary);
	showRykWidget(ctx, card);
	const choiceLabel = await ctx.ui?.select?.(
		`${PRODUCT_NAME}: needs your decision`,
		askOptionsFor("policy", allowOnce),
		{ timeout: 60_000, signal: ctx.signal },
	);
	const choice = mapSelectLabelToChoice(choiceLabel);
	clearRykWidget(ctx);

	const sessionId = ctx.sessionManager?.getSessionId?.()?.trim();
	const root = askIpc?.askRoot ?? resolvePiAskRoot(env, askIpc?.askFs);
	const now = askIpc?.askNow ?? Date.now;

	if (choice === "allow_session_tool" && sessionId) {
		addSessionGrant(
			parentAskDir(root, sessionId, askIpc?.askFs),
			toolLabel,
			now(),
			askIpc?.askFs,
		);
		notify(
			ctx,
			`Allowed ${toolLabel} for this Pi session (session grant).`,
			"warning",
		);
		return undefined;
	}

	switch (choice) {
		case "run_once":
			if (!allowOnce) {
				return block(
					formatAgentBlockReason(
						{
							variant: "block",
							title: DISPLAY_BRAND,
							summary,
						},
						toolLabel,
					),
				);
			}
			if (!recordOnceBypass(pi, ctx, toolLabel, "policy")) {
				return block(
					"ryk blocked this once-bypass because a required transcript audit event could not be recorded.",
				);
			}
			notify(
				ctx,
				`Allowed this ${toolLabel} action once without ryk evaluation.`,
				"warning",
			);
			return undefined;
		case "disable_session":
			actions.disableSession();
			notify(
				ctx,
				`${PRODUCT_NAME} disabled for this session only. Use /ryk-start to re-enable.`,
				"warning",
			);
			return undefined;
		case "show_reason":
			notify(ctx, summary, "error");
			return block(
				formatAgentBlockReason(
					{
						variant: "block",
						title: DISPLAY_BRAND,
						summary,
					},
					toolLabel,
				),
			);
		case "block":
		default:
			// Timeout / undefined / unknown choice → block only (never allow).
			return block(
				formatAgentBlockReason(
					{
						variant: "block",
						title: DISPLAY_BRAND,
						summary,
					},
					toolLabel,
				),
			);
	}
}

async function handleUnavailable(
	reason: string,
	pi: PiAPI,
	ctx: PiContext,
	mode: EffectiveUnavailableMode,
	_actions: { disableSession: () => void },
	toolLabel = "bash",
	_allowOnce = true,
	session?: SessionState,
	_env: NodeJS.ProcessEnv = process.env,
	_askIpc?: AskIpcContext,
): Promise<ToolCallResult> {
	const repair = repairMessage(reason, toolLabel);
	const failureClass = protocolFailureClassFromReason(reason);

	// Sticky session recovery: prior block sticks for this session.
	if (session?.protocolRecovery === "block") {
		const card = {
			variant: "block" as const,
			title: DISPLAY_BRAND,
			summary: repair,
		};
		showRykDecision(pi, ctx, card);
		return block(formatAgentBlockReason(card, toolLabel));
	}

	// allow-with-warning remains an explicit opt-in mode (not the default).
	// It soft-allows only spawn_failed. Protocol corruption always fail-closes.
	if (
		mode === "allow-with-warning" &&
		allowWithWarningPermitsProtocolClass(failureClass)
	) {
		clearRykWidget(ctx);
		notify(
			ctx,
			`ryk unavailable; allowing ${toolLabel} with warning. ${repair}`,
			"warning",
		);
		return undefined;
	}

	// No host ask. Protocol failure is fail-closed block.
	if (session) session.protocolRecovery = "block";
	const card = {
		variant: "block" as const,
		title: DISPLAY_BRAND,
		summary: repair,
	};
	showRykDecision(pi, ctx, card);
	return block(formatAgentBlockReason(card, toolLabel));
}

async function setupRyk(
	ctx: PiContext,
	runtime: Required<
		Pick<RykExtensionOptions, "rykBin" | "spawn" | "timeoutMs">
	> & { env?: NodeJS.ProcessEnv },
): Promise<SetupResult> {
	const cwd = resolveCwd(ctx.cwd);
	const policyPath = resolve(cwd, ".ryk", "policy.yaml");
	if (!existsSync(policyPath)) {
		const init = await runRykCommand(
			["init", "--preset", "generic-agent"],
			runtime,
			cwd,
		);
		if (init.error) return { status: "missing", message: rykInstallMessage() };
		if (init.code !== 0 || !existsSync(policyPath)) {
			return {
				status: "degraded",
				message: `ryk policy setup failed (exit ${init.code ?? "unknown"}). ${summarizeCommandOutput(init)}`,
			};
		}
	}

	const doctor = await runRykCommand(["doctor"], runtime, cwd);
	if (doctor.error) return { status: "missing", message: rykInstallMessage() };
	if (doctor.code !== 0) {
		return {
			status: "degraded",
			message: `ryk policy is ready, but the health probe exited with ${doctor.code ?? "unknown"}. ${summarizeCommandOutput(doctor)}`,
		};
	}
	return {
		status: "ready",
		message: "ryk policy is ready and health checks passed.",
	};
}

function runProcess(
	file: string,
	args: string[],
	stdin: string | undefined,
	spawn: SpawnLike,
	timeoutMs: number,
	env?: NodeJS.ProcessEnv,
	cwd?: string,
): Promise<RunProcessResult> {
	return new Promise((resolvePromise) => {
		const controller = new AbortController();
		let stdout = "";
		let stderr = "";
		let settled = false;
		let timedOut = false;
		let outputExceeded = false;
		const timer = setTimeout(() => {
			timedOut = true;
			controller.abort();
		}, timeoutMs);

		const settle = (result: RunProcessResult): void => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolvePromise({ ...result, stdout, stderr, timedOut });
		};

		let child: ChildLike;
		try {
			child = spawn(file, args, {
				stdio: [stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
				shell: false,
				signal: controller.signal,
				env,
				cwd,
			});
		} catch (error) {
			settle({ code: null, stdout, stderr, error: asError(error), timedOut });
			return;
		}

		child.stdout?.on("data", (chunk) => {
			const appended = appendBounded(
				stdout,
				String(chunk),
				MAX_CHILD_OUTPUT_BYTES,
			);
			stdout = appended.text;
			if (appended.exceeded && !outputExceeded) {
				outputExceeded = true;
				settle({
					code: null,
					stdout,
					stderr,
					error: new Error("ryk output exceeded maximum size"),
					timedOut,
				});
				controller.abort();
			}
		});
		child.stderr?.on("data", (chunk) => {
			const appended = appendBounded(
				stderr,
				String(chunk),
				MAX_CHILD_OUTPUT_BYTES,
			);
			stderr = appended.text;
			if (appended.exceeded && !outputExceeded) {
				outputExceeded = true;
				settle({
					code: null,
					stdout,
					stderr,
					error: new Error("ryk output exceeded maximum size"),
					timedOut,
				});
				controller.abort();
			}
		});
		child.on("error", (errorOrCode: Error | number | null) => {
			settle({
				code: null,
				stdout,
				stderr,
				error: asError(errorOrCode),
				timedOut,
			});
		});
		child.on("close", (codeOrError: Error | number | null) => {
			settle({
				code: typeof codeOrError === "number" ? codeOrError : null,
				stdout,
				stderr,
				timedOut,
			});
		});

		if (stdin !== undefined) {
			child.stdin?.write(stdin);
			child.stdin?.end();
		}
	});
}

function sessionKey(ctx: PiContext): string {
	try {
		const id = ctx.sessionManager?.getSessionId?.();
		if (id) return id;
	} catch {
		// Fall through to the local test fallback.
	}
	return "__default_session__";
}

function resolveBundledPackageRoot(): string | undefined {
	try {
		const require = createRequire(import.meta.url);
		return dirname(require.resolve("@rykan/ryk/package.json"));
	} catch {
		return undefined;
	}
}

function isExecutableFile(path: string): boolean {
	try {
		accessSync(
			path,
			process.platform === "win32" ? constants.F_OK : constants.X_OK,
		);
		return true;
	} catch {
		return false;
	}
}

/** Prefer ryk on PATH; version line must say ryk (hard-cut: no ryk dual-read). */
function resolveCompatiblePathCli(
	env: NodeJS.ProcessEnv,
	runner: SpawnSyncLike,
): string | null {
	const versionRe = new RegExp(
		`\\bryk\\s+${REQUIRED_RYK_VERSION.replaceAll(".", "\\.")}\\b`,
	);
	const result = runner("ryk", ["--version"], {
		encoding: "utf8",
		env,
		shell: false,
		timeout: 2_000,
	});
	if (result.error || result.status !== 0) return null;
	if (versionRe.test(result.stdout ?? "")) return "ryk";
	return null;
}

function appendBounded(
	current: string,
	chunk: string,
	maxBytes: number,
): { text: string; exceeded: boolean } {
	const currentBytes = Buffer.byteLength(current);
	const chunkBytes = Buffer.byteLength(chunk);
	if (currentBytes + chunkBytes <= maxBytes)
		return { text: current + chunk, exceeded: false };
	const remaining = Math.max(0, maxBytes - currentBytes);
	return { text: current + chunk.slice(0, remaining), exceeded: true };
}

function resolveCwd(cwd: string | undefined): string {
	const candidate = cwd ? resolve(cwd) : process.cwd();
	return existsSync(candidate) ? candidate : process.cwd();
}

function block(reason: string): ToolCallBlock {
	return { block: true, reason: sanitizeVisibleText(reason) };
}

function clearRykWidget(ctx: PiContext): void {
	ctx.ui?.setWidget?.(BLOCK_WIDGET_KEY, undefined);
}

function showRykWidget(ctx: PiContext, card: RykDecisionCard): void {
	if (!ctx.ui?.setWidget) return;
	ctx.ui.setWidget(BLOCK_WIDGET_KEY, buildRykWidget(card), {
		placement: "aboveEditor",
	});
}

function showRykDecision(
	pi: PiAPI,
	ctx: PiContext,
	card: RykDecisionCard,
): void {
	clearRykWidget(ctx);
	if (pi.sendMessage) {
		pi.sendMessage(
			{
				customType: DECISION_CUSTOM_TYPE,
				content: buildRykWidget(card).join("\n"),
				display: true,
				details: card,
			},
			{ triggerTurn: false },
		);
		return;
	}

	// Older Pi hosts cannot append transcript messages. Keep their docked fallback
	// isolated here; supported hosts always use the conversation surface above.
	showRykWidget(ctx, card);
}

/** Borderless decision card — brand header, no ASCII box frame. */
export function buildRykWidget(card: RykDecisionCard): string[] {
	return buildThemedDecisionLines(card, PLAIN_THEME);
}

function decisionCardRows(
	card: RykDecisionCard,
): Array<{ label: string; value: string }> {
	const rows: Array<{ label: string; value: string }> = [];
	if (card.summary) rows.push({ label: "Why", value: card.summary });
	if (card.preview) rows.push({ label: "Cmd", value: card.preview });
	const metaBits: string[] = [];
	if (card.rule) metaBits.push(card.rule);
	if (card.severity) metaBits.push(capitalize(card.severity));
	if (card.pack && card.pack !== card.rule?.split(":")[0]) {
		metaBits.push(card.pack);
	}
	if (metaBits.length > 0) {
		rows.push({ label: "Meta", value: metaBits.join(" · ") });
	}
	if (card.nextStep) rows.push({ label: "Next", value: card.nextStep });
	if (card.variant === "wait" && card.timeoutHint) {
		rows.push({ label: "Wait", value: card.timeoutHint });
	}
	// Ask only: real choices come from ui.select — one quiet hint, never fake buttons.
	if (card.variant === "ask") {
		rows.push({
			label: "Tip",
			value: "Use the prompt below to Allow once, Allow for session, or Deny.",
		});
	}
	return rows;
}

function terminalContentWidth(): number {
	const cols = Number(process.stdout?.columns ?? 0);
	if (!Number.isFinite(cols) || cols < 40) return 54;
	return Math.max(40, cols - 8);
}

function buildRykDecisionCard(
	response: unknown,
	variant: "block" | "ask",
): RykDecisionCard {
	const reason = getDecisionReason(response);
	const rule = getRuleId(response);
	const pack = getStringFieldAny(response, ["pack_id", "packId"]);
	const severity = getStringFieldAny(response, ["severity"]);
	const nextStep = getNextStep(response);
	return {
		variant,
		title: DISPLAY_BRAND,
		summary: sanitizeVisibleText(reason),
		rule,
		pack,
		severity,
		nextStep,
	};
}

function buildRykAskCard(reason: string): RykDecisionCard {
	return {
		variant: "ask",
		title: DISPLAY_BRAND,
		summary: sanitizeVisibleText(reason),
	};
}

function buildRykWaitCard(input: {
	toolLabel: string;
	reason: string;
	commandOrName?: string;
	timeoutMs: number;
}): RykDecisionCard {
	const secs = Math.max(1, Math.round(input.timeoutMs / 1000));
	const preview =
		input.commandOrName && input.commandOrName !== input.toolLabel
			? truncate(sanitizeVisibleText(input.commandOrName), 96)
			: undefined;
	return {
		variant: "wait",
		title: DISPLAY_BRAND,
		summary: sanitizeVisibleText(
			`Waiting for approval in the parent Pi session (${input.toolLabel}).`,
		),
		preview,
		nextStep:
			"Switch to the main Pi window and answer the prompt. This card is not interactive.",
		timeoutHint: `Auto-denies in ~${secs}s if unanswered.`,
		rule: "rykanv:parent-ask-wait",
	};
}

function formatRykDecisionSummary(
	card: RykDecisionCard,
	toolLabel = "bash",
): string {
	const parts = [card.summary];
	if (card.rule) parts.push(`rule ${card.rule}`);
	if (card.pack && card.pack !== card.rule?.split(":")[0])
		parts.push(`pack ${card.pack}`);
	if (card.severity) parts.push(`severity ${card.severity}`);
	const action = toolLabel === "bash" ? "bash command" : `${toolLabel} action`;
	const verb =
		card.variant === "ask" || card.variant === "wait"
			? "needs your decision"
			: `blocked this ${action}`;
	return sanitizeVisibleText(`${PRODUCT_NAME} ${verb}: ${parts.join(" • ")}`);
}

function getDecisionReason(response: unknown): string {
	return (
		getStringFieldAny(response, ["reason", "message"]) ??
		getNestedStringField(response, ["error", "message"]) ??
		"ryk blocked this action."
	);
}

function getRuleId(response: unknown): string | undefined {
	// Evaluate uses rule_id; decide file uses `rule`. normalizeDecideToEvaluateShape
	// maps rule → rule_id, but accept both so cards stay robust.
	return getStringFieldAny(response, ["rule_id", "ruleId", "rule"]);
}

function getNextStep(response: unknown): string | undefined {
	const remediation = Array.isArray(
		(response as RykEvaluateResponse | null)?.remediation,
	)
		? (response as RykEvaluateResponse).remediation
		: undefined;
	const description = remediation?.find(
		(entry) => entry?.description,
	)?.description;
	return description ? sanitizeVisibleText(description) : undefined;
}

function getStringFieldAny(value: unknown, keys: string[]): string | undefined {
	for (const key of keys) {
		const field = getStringField(value, key);
		if (field) return field;
	}
	return undefined;
}

function capitalize(value: string): string {
	return value.charAt(0).toUpperCase() + value.slice(1);
}

function wrapText(value: string, width: number): string[] {
	const text = sanitizeVisibleText(value);
	if (!text) return [""];
	const words = text.split(/\s+/);
	const lines: string[] = [];
	let current = "";
	for (const word of words) {
		if (!current) {
			current = word;
			continue;
		}
		if (`${current} ${word}`.length <= width) {
			current = `${current} ${word}`;
			continue;
		}
		lines.push(current);
		current = word;
	}
	if (current) lines.push(current);
	return lines.flatMap((line) => {
		if (line.length <= width) return [line];
		const chunks: string[] = [];
		for (let i = 0; i < line.length; i += width)
			chunks.push(line.slice(i, i + width));
		return chunks;
	});
}

const MINIMAL_LABEL_WIDTH = 4;

/**
 * Borderless labeled row. Optional `paint` styles label/value for the themed
 * transcript renderer; plaintext widgets omit it.
 */
function formatMinimalRow(
	label: string,
	value: string | undefined,
	width: number,
	paint?: (labelCol: string, valuePart: string, first: boolean) => string,
): string[] {
	if (!value) return [];
	const labelCol = label.padEnd(MINIMAL_LABEL_WIDTH);
	const available = Math.max(1, width - MINIMAL_LABEL_WIDTH - 2);
	const wrapped = wrapText(value, available);
	return wrapped.map((line, index) => {
		const prefix =
			index === 0 ? labelCol : "".padEnd(MINIMAL_LABEL_WIDTH, " ");
		const raw = `${prefix}  ${line}`;
		if (!paint) return raw;
		return paint(prefix, `  ${line}`, index === 0);
	});
}

function notify(
	ctx: PiContext,
	message: string,
	type: "info" | "warning" | "error",
): void {
	// Host UI is best-effort; never alter allow/deny control flow.
	try {
		ctx.ui?.notify?.(truncate(sanitizeVisibleText(message), 2_000), type);
	} catch {
		// Swallow notify transport failures.
	}
}

/** Drop Recourse/Next operator walls from short flash / agent Why atoms. */
function stripOperatorWalls(text: string): string {
	// Collapse whitespace first so walls after newlines still match `.*$`.
	const cleaned = sanitizeVisibleText(text)
		.replace(/\s*Recourse:\s*.*$/i, "")
		.replace(/\s*Next:\s*.*$/i, "")
		.trim();
	// Never reintroduce walls when the entire atom was operator paste.
	return cleaned || "ryk blocked this action.";
}

/**
 * Short card/block copy for protocol failures (fits 54-col widget).
 * Prefer the class token already present in `reason` over a second "Failure class" line.
 * Always ends with Fail-closed + doctor hint so the card stays actionable.
 */
export function repairMessage(reason: string, toolLabel = "bash"): string {
	const cleaned = sanitizeVisibleText(reason);
	const core = cleaned.startsWith("[")
		? cleaned
		: `could not evaluate ${toolLabel}: ${cleaned}`;
	const suffix = " Fail-closed. /ryk-doctor";
	const max = 220;
	if (core.length + suffix.length <= max) return `${core}${suffix}`;
	const budget = Math.max(24, max - suffix.length - 1);
	return `${core.slice(0, budget)}…${suffix}`;
}

/** Longer notify/doctor copy; still avoids the old coverage wall of text. */
export function repairMessageDetail(reason: string, toolLabel = "bash"): string {
	const short = repairMessage(reason, toolLabel);
	return `${short} Not a permanent session brick. Retry the tool, or /ryk-setup then /ryk-doctor.`;
}

function modeSummary(mode: UnavailableMode, sessionBypass: boolean): string {
	return [
		`ryk Pi mode: ${mode}`,
		`Session bypass: ${sessionBypass ? "on" : "off"}`,
		`Coverage: ${piCoverageLabel()}`,
		`Once-bypass: ${allowOnceBypassEnabled(process.env, mode) ? "allowed" : "disabled"} (RYK_PI_ALLOW_ONCE; strict disables by default)`,
		"Default RYK_PI_MODE=auto (protocol failure fail-closes; residual policy ask is permit). Production: prefer strict. allow-with-warning is never the default.",
		"Modes: auto, ask, noninteractive-block, strict, allow-with-warning.",
		"Process-level env/network/secretless requires: ryk run [--secretless] [--network …] -- pi …",
	].join("\n");
}

function rykInstallMessage(): string {
	return "ryk bundled Pi protection was not found. Re-run the ryk installer, then run /ryk-setup.";
}

function summarizeCommandOutput(result: RunProcessResult): string {
	const output = result.stdout.trim() || result.stderr.trim();
	return truncate(sanitizeVisibleText(output), 2_000);
}

function parseMode(value: string | undefined): UnavailableMode | undefined {
	if (
		value === "auto" ||
		value === "ask" ||
		value === "noninteractive-block" ||
		value === "strict" ||
		value === "allow-with-warning"
	) {
		return value;
	}
	return undefined;
}

function sanitizeVisibleText(value: string): string {
	return (
		value
			.replace(/\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, "[redacted-token]")
			.replace(/\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b/g, "[redacted-token]")
			.replace(
				/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
				"[redacted-token]",
			)
			.replace(/[A-Za-z0-9_]*gh[pousr]_[A-Za-z0-9_]+/g, "[redacted-token]")
			.replace(/(password|token|secret|api[_-]?key)=\S+/gi, "$1=[redacted]")
			.replace(/\s+/g, " ")
			.trim()
	);
}

function truncate(value: string, max: number): string {
	if (value.length <= max) return value;
	return `${value.slice(0, max - 3)}...`;
}

function getStringField(value: unknown, key: string): string | undefined {
	if (!value || typeof value !== "object") return undefined;
	const field = (value as Record<string, unknown>)[key];
	return typeof field === "string" ? field : undefined;
}

function getNestedStringField(
	value: unknown,
	path: string[],
): string | undefined {
	let current = value;
	for (const segment of path) {
		if (!current || typeof current !== "object") return undefined;
		current = (current as Record<string, unknown>)[segment];
	}
	return typeof current === "string" ? current : undefined;
}

function asError(value: unknown): Error {
	return value instanceof Error ? value : new Error(String(value));
}

export default function rykPiExtension(pi: PiAPI): void {
	installRykExtension(pi);
}
