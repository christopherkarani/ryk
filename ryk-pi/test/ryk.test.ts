import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import {
	writeAskRequest,
	type ParentAskFs,
} from "../extensions/parent_ask.ts";
import {
	allowOnceBypassEnabled,
	askOptionsFor,
	buildAutoDenyCopy,
	buildDecideFilePayload,
	buildDecideToolPayload,
	buildEvaluateRequest,
	DISPLAY_BRAND,
	extractDecideFilePath,
	installRykExtension,
	isPassthroughPiTool,
	isProtectedPiTool,
	isSubagentSession,
	listPendingRequests,
	mapSelectLabelToChoice,
	parentAskDir,
	piCoverageLabel,
	PRODUCT_NAME,
	repairMessage,
	resolveRykBin,
	resolvePiAskRoot,
	resolveToolPath,
	resolveUnavailableMode,
	buildRykWidget,
	buildThemedDecisionLines,
	formatAgentBlockReason,
	formatProtocolErrorReason,
	formatMalformedJsonDetail,
	previewProcessOutput,
	protocolFailureClassFromReason,
	isTransientProtocolFailure,
	allowWithWarningPermitsProtocolClass,
	runRykDecideFile,
	runRykDecideTool,
	runRykEvaluate,
	safeRykReason,
	SESSION_GRANT_OPTION,
	shouldAutoDenyPolicyAsk,
	shouldLocalSelectPolicyAsk,
	shouldNameGateTool,
	writeAskResponse,
	addSessionGrant,
	hasSessionGrant,
	PROTOCOL_DEGRADED_THRESHOLD,
	type RykEvaluateRequest,
} from "../extensions/ryk.ts";

type Handler = (event: any, ctx: any) => Promise<any> | any;

const packageJson = JSON.parse(
	readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as {
	dependencies: Record<string, string>;
};
const requiredRuntimeVersion =
	packageJson.dependencies["@rykan/ryk"] ??
	"1.2.9";

class FakeChild {
	stdinWrites: string[] = [];
	stdout = new EventEmitter();
	stderr = new EventEmitter();
	stdin = {
		write: (data: string) => {
			this.stdinWrites.push(data);
		},
		end: () => {},
	};
	private emitter = new EventEmitter();

	on(event: "error" | "close", handler: (...args: any[]) => void): void {
		this.emitter.on(event, handler);
	}

	close(code: number | null): void {
		this.emitter.emit("close", code);
	}

	fail(error: Error): void {
		this.emitter.emit("error", error);
	}
}

function makeSpawn(
	plans: Array<{
		code?: number | null;
		stdout?: string;
		stderr?: string;
		error?: Error;
		run?: (call: {
			file: string;
			args: string[];
			options: any;
			stdin: string[];
		}) => void;
	}> = [],
) {
	const calls: Array<{
		file: string;
		args: string[];
		options: any;
		stdin: string[];
	}> = [];
	const spawn = (file: string, args: string[], options: any): FakeChild => {
		const child = new FakeChild();
		const call = { file, args, options, stdin: child.stdinWrites };
		calls.push(call);
		const plan = plans.shift() ?? { code: 0, stdout: allowJson() };
		queueMicrotask(() => {
			plan.run?.(call);
			if (plan.stdout) child.stdout.emit("data", plan.stdout);
			if (plan.stderr) child.stderr.emit("data", plan.stderr);
			if (plan.error) child.fail(plan.error);
			else child.close(plan.code === undefined ? 0 : plan.code);
		});
		return child;
	};
	return { spawn, calls };
}

async function flushAsyncWork(): Promise<void> {
	await new Promise<void>((resolvePromise) => setImmediate(resolvePromise));
	await new Promise<void>((resolvePromise) => setImmediate(resolvePromise));
}

type MessageRenderer = (
	message: {
		customType: string;
		content: string;
		display: boolean;
		details?: unknown;
	},
	options: { expanded: boolean; outputPad: number },
	theme: {
		fg: (color: string, text: string) => string;
		bg?: (color: string, text: string) => string;
		bold?: (text: string) => string;
		dim?: (text: string) => string;
	},
) => unknown;

function makeThemeStub() {
	return {
		fg: (color: string, text: string) => `[${color}]${text}[/${color}]`,
		bg: (color: string, text: string) => `{${color}}${text}{/${color}}`,
		bold: (text: string) => text,
		dim: (text: string) => text,
	};
}

function makePi() {
	const handlers = new Map<string, Handler[]>();
	const commands = new Map<
		string,
		{ handler: (args: string | undefined, ctx: any) => Promise<void> | void }
	>();
	const messages: Array<{
		message: {
			customType: string;
			content: string;
			display: boolean;
			details?: unknown;
		};
		options?: { triggerTurn?: boolean; deliverAs?: string };
	}> = [];
	const renderers = new Map<string, MessageRenderer>();
	const pi = {
		on(event: string, handler: Handler) {
			const list = handlers.get(event) ?? [];
			list.push(handler);
			handlers.set(event, list);
		},
		registerCommand(name: string, options: any) {
			commands.set(name, options);
		},
		sendMessage(message: any, options?: any) {
			messages.push({ message, options });
		},
		registerMessageRenderer(customType: string, renderer: MessageRenderer) {
			renderers.set(customType, renderer);
		},
	};
	return { pi, handlers, commands, messages, renderers };
}

function makeCtx(overrides: Record<string, unknown> = {}) {
	const notifications: Array<{ message: string; type?: string }> = [];
	const statuses: Array<{ key: string; text: string | undefined }> = [];
	const widgets: Array<{
		key: string;
		value: string[] | undefined;
		opts?: { placement?: "aboveEditor" | "belowEditor" };
	}> = [];
	const selections: string[] = [];
	const ctx = {
		cwd: process.cwd(),
		mode: "tui",
		hasUI: true,
		sessionManager: { getSessionId: () => "session-a" },
		ui: {
			notify: (message: string, type?: string) =>
				notifications.push({ message, type }),
			setStatus: (key: string, text: string | undefined) =>
				statuses.push({ key, text }),
			setWidget: (
				key: string,
				value: undefined | string[],
				opts?: { placement?: "aboveEditor" | "belowEditor" },
			) => widgets.push({ key, value, opts }),
			select: async () => selections.shift(),
		},
		...overrides,
	};
	return { ctx, notifications, statuses, widgets, selections };
}

const UNATTENDED_ENV_KEYS = [
	"CI",
	"RYK_CI",
	"RYK_NONINTERACTIVE",
	"RYK_UNATTENDED",
] as const;

/** Residual-ask permit tests must not inherit GitHub Actions CI=true. */
async function withClearedUnattendedEnv<T>(
	run: () => Promise<T> | T,
): Promise<T> {
	const saved = Object.fromEntries(
		UNATTENDED_ENV_KEYS.map((key) => [key, process.env[key]]),
	);
	for (const key of UNATTENDED_ENV_KEYS) delete process.env[key];
	try {
		return await run();
	} finally {
		for (const key of UNATTENDED_ENV_KEYS) {
			if (saved[key] === undefined) delete process.env[key];
			else process.env[key] = saved[key];
		}
	}
}

function allowJson(): string {
	return JSON.stringify({
		decision: "allow",
		reason: "Command allowed",
		daemon: { status: "healthy", compatible: true },
	});
}

function denyJson(): string {
	return JSON.stringify({
		decision: "deny",
		reason: "destructive filesystem command",
		rule_id: "core.filesystem:destructive-rm",
		daemon: { status: "healthy", compatible: true },
	});
}

function askJson(): string {
	return JSON.stringify({
		decision: "ask",
		reason: "requires approval in ask mode; would deny in strict",
		severity: "high",
		rule_id: "core.git:force-push",
		daemon: { status: "healthy", compatible: true },
	});
}

function errorJson(): string {
	return JSON.stringify({
		decision: "error",
		reason: "daemon is unavailable for shell-command evaluation",
		error: { code: "daemon_unavailable", message: "daemon unavailable" },
	});
}

test("resolveRykBin honors executable RYK_BIN before other candidates", () => {
	const result = resolveRykBin({
		env: { RYK_BIN: "/trusted/ryk" },
		bundledPackageRoot: "/package",
		isExecutable: (path) => path === "/trusted/ryk",
		isPathCompatible: () => true,
	});

	assert.deepEqual(result, { rykBin: "/trusted/ryk", source: "explicit" });
});


test("resolveRykBin ignores the removed ORCA_BIN alias", () => {
	const result = resolveRykBin({
		env: { ORCA_BIN: "/old/ryk" },
		bundledPackageRoot: "/package",
		isExecutable: (path) => path === "/old/ryk",
		isPathCompatible: () => true,
	});
	assert.deepEqual(result, {
		rykBin: "__ryk_bundled_runtime_missing__",
		source: "missing",
	});
});

test("resolveRykBin prefers the bundled runtime and requires opt-in for PATH", () => {
	const defaults = {
		bundledPackageRoot: "/package",
		// Prefer ryk vendor binary when present (Phase 5a).
		isExecutable: (path: string) =>
				path.includes("/vendor/ryk") ||
				path.includes("/vendor/ryk-daemon"),
		isPathCompatible: () => true,
	};

	assert.deepEqual(resolveRykBin({ ...defaults, env: {} }), {
		rykBin: resolve("/package/vendor/ryk"),
		daemonBin: resolve("/package/vendor/ryk-daemon"),
		source: "bundled",
	});
	// A different vendor binary is not a bundled ryk runtime.
	assert.deepEqual(
		resolveRykBin({
			...defaults,
			isExecutable: (path: string) => path.includes("/vendor/other-runtime"),
			env: {},
		}),
		{
			rykBin: "__ryk_bundled_runtime_missing__",
			source: "missing",
		},
	);
	assert.deepEqual(
		resolveRykBin({
			...defaults,
			bundledPackageRoot: "/missing-package",
			isExecutable: () => false,
			env: { RYK_PI_USE_PATH: "true" },
		}),
		{
			rykBin: "ryk",
			source: "path",
		},
	);
});

test("resolveRykBin uses bundled ryk when PATH is incompatible", () => {
	const result = resolveRykBin({
		env: {},
		bundledPackageRoot: "/package",
		isExecutable: () => true,
		isPathCompatible: () => false,
	});

	assert.equal(result.rykBin, resolve("/package/vendor/ryk"));
	assert.equal(result.daemonBin, resolve("/package/vendor/ryk-daemon"));
	assert.equal(result.source, "bundled");
});

test("resolveRykBin validates opted-in PATH version output", () => {
	const compatible = resolveRykBin({
		env: { RYK_PI_USE_PATH: "true" },
		bundledPackageRoot: "/missing-package",
		isExecutable: () => false,
		spawnSync: (cmd: string) => ({
			status: 0,
		stdout: `ryk ${requiredRuntimeVersion}\n`,
		}),
	});
	assert.equal(compatible.source, "path");
	assert.equal(compatible.rykBin, "ryk");

	for (const result of [
		{ status: 0, stdout: "other-runtime 0.0.0\n" },
		{ status: 0, stdout: "not-ryk\n" },
		{ status: 1, stdout: `ryk ${requiredRuntimeVersion}\n` },
		{ status: null, stdout: "", error: new Error("timeout") },
	]) {
		assert.equal(
			resolveRykBin({
				env: { RYK_PI_USE_PATH: "true" },
				bundledPackageRoot: "/missing-package",
				isExecutable: () => false,
				spawnSync: () => result,
			}).source,
			"missing",
		);
	}
});

test("bundled ryk evaluation receives its companion daemon path", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([{ code: 0, stdout: allowJson() }]);
	installRykExtension(pi, {
		spawn,
		resolveBin: () => ({
			rykBin: "/package/vendor/ryk",
			daemonBin: "/package/vendor/ryk-daemon",
			source: "bundled",
		}),
	});

	await fireToolCall(handlers.get("tool_call")![0], makeCtx().ctx);

	assert.equal(calls[0].options.env.RYK_DAEMON, "/package/vendor/ryk-daemon");
});

test("session start quietly initializes a missing policy and probes health", async () => {
	const cwd = mkdtempSync(resolve(tmpdir(), "ryk-pi-"));
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([
		{
			code: 0,
			run: (call) => {
				mkdirSync(resolve(call.options.cwd, ".ryk"));
				writeFileSync(
					resolve(call.options.cwd, ".ryk/policy.yaml"),
					"version: 1\n",
				);
			},
		},
		{ code: 0, stdout: "healthy" },
	]);
	const context = makeCtx({ cwd });
	installRykExtension(pi, { spawn, rykBin: "ryk" });

	const returned = handlers.get("session_start")![0]({}, context.ctx);
	assert.equal(returned, undefined);
	await flushAsyncWork();

	assert.deepEqual(
		calls.map((call) => call.args),
		[["init", "--preset", "generic-agent"], ["doctor"]],
	);
	assert.deepEqual(
		calls.map((call) => call.options.cwd),
		[cwd, cwd],
	);
	assert.equal(context.notifications.length, 0);
	assert.equal(context.statuses.at(-1)?.text, "rykan v ready");
	assert.equal(context.statuses.at(-1)?.key, "rykanv");
	assert.ok(
		context.statuses.every(
			(entry) =>
				entry.text === undefined ||
				entry.text === "rykan v degraded" ||
				entry.text === "rykan v ready" ||
				entry.text === "rykan v bypass",
		),
		"expected footer status to contain rykan v state only",
	);
	rmSync(cwd, { recursive: true, force: true });
});

test("first bash evaluation waits for non-blocking session bootstrap", async () => {
	const cwd = mkdtempSync(resolve(tmpdir(), "ryk-pi-"));
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([
		{
			code: 0,
			run: (call) => {
				mkdirSync(resolve(call.options.cwd, ".ryk"));
				writeFileSync(
					resolve(call.options.cwd, ".ryk/policy.yaml"),
					"version: 1\n",
				);
			},
		},
		{ code: 0, stdout: "healthy" },
		{ code: 0, stdout: allowJson() },
	]);
	const context = makeCtx({ cwd });
	installRykExtension(pi, { spawn, rykBin: "ryk" });

	assert.equal(handlers.get("session_start")![0]({}, context.ctx), undefined);
	const decision = await fireToolCall(
		handlers.get("tool_call")![0],
		context.ctx,
	);

	assert.equal(decision, undefined);
	assert.deepEqual(
		calls.map((call) => call.args),
		[
			["init", "--preset", "generic-agent"],
			["doctor"],
			["evaluate", "--json", "--stdin"],
		],
	);
	assert.deepEqual(
		calls.map((call) => call.options.cwd),
		[cwd, cwd, cwd],
	);
	rmSync(cwd, { recursive: true, force: true });
});

test("/ryk-setup ensures policy and probes health without invoking start", async () => {
	const cwd = mkdtempSync(resolve(tmpdir(), "ryk-pi-"));
	const { pi, commands } = makePi();
	const { spawn, calls } = makeSpawn([
		{
			code: 0,
			run: (call) => {
				mkdirSync(resolve(call.options.cwd, ".ryk"));
				writeFileSync(
					resolve(call.options.cwd, ".ryk/policy.yaml"),
					"version: 1\n",
				);
			},
		},
		{ code: 0, stdout: "healthy" },
	]);
	const context = makeCtx({ cwd });
	installRykExtension(pi, { spawn, rykBin: "ryk" });

	await commands.get("ryk-setup")!.handler("", context.ctx);

	assert.deepEqual(
		calls.map((call) => call.args),
		[["init", "--preset", "generic-agent"], ["doctor"]],
	);
	assert.deepEqual(
		calls.map((call) => call.options.cwd),
		[cwd, cwd],
	);
	assert.equal(
		calls.some((call) => call.args.includes("start")),
		false,
	);
	assert.equal(context.notifications.at(-1)?.type, "info");
	rmSync(cwd, { recursive: true, force: true });
});

async function fireToolCall(
	handler: Handler,
	ctx: any,
	command = "git status",
	toolName = "bash",
	input?: Record<string, unknown>,
) {
	const payload =
		input ??
		(toolName === "bash"
			? { command }
			: { path: command, content: "x" });
	return handler({ toolName, input: payload }, ctx);
}

function decideBlockJson(
	rule = "files.write.deny[0]",
	category = "file.write",
): string {
	return JSON.stringify({
		version: 1,
		decision: "block",
		risk: "high",
		category,
		reason: `matched ${category} deny rule`,
		rule,
		message: `${category} blocked by ryk policy.`,
		redactions: [],
	});
}

function decideAllowJson(category = "file.write"): string {
	return JSON.stringify({
		version: 1,
		decision: "allow",
		risk: "low",
		category,
		reason: "default allow",
		rule: null,
		message: `${category} allowed by ryk policy.`,
		redactions: [],
	});
}

function decideJson(
	decision:
		| "allow"
		| "block"
		| "ask"
		| "stage"
		| "warn"
		| "context_only"
		| "error",
	category = "file.write",
): string {
	return JSON.stringify({
		version: 1,
		decision,
		risk: "low",
		category,
		reason: `${category} returned ${decision}`,
		rule: null,
		message: `${category} returned ${decision}`,
		redactions: [],
	});
}

test("decide file rejects context_only for write side effects", async () => {
	const { spawn } = makeSpawn([
		{ code: 0, stdout: decideJson("context_only") },
	]);
	const result = await runRykDecideFile(
		{ path: "./src/main.ts", operation: "write" },
		{ spawn, rykBin: "ryk", timeoutMs: 1_000, cwd: process.cwd() },
	);
	assert.equal(result.kind, "deny");
});

test("decide file validates decision and exit-code consistency", async () => {
	for (const plan of [
		{ code: 1, stdout: decideJson("allow") },
		{ code: 0, stdout: decideJson("block") },
		{ code: 0, stdout: decideJson("ask") },
		{ code: 0, stdout: decideJson("warn") },
		{ code: null, stdout: decideJson("allow") },
		{ code: 0, stdout: "" },
	]) {
		// Retry once on protocol error; both attempts fail → still fail-closed.
		const { spawn } = makeSpawn([plan, plan]);
		const result = await runRykDecideFile(
			{ path: "./README.md", operation: "read" },
			{ spawn, rykBin: "ryk", timeoutMs: 1_000, cwd: process.cwd() },
		);
		assert.equal(result.kind, "error", JSON.stringify(plan));
		if (result.kind === "error") {
			assert.match(result.reason, /\[[a-z_]+\]/);
		}
	}
});

test("custom/MCP-shaped tools are name-gated via ryk decide tool", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([
		{ code: 0, stdout: decideAllowJson("tool") },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ cwd: process.cwd() });

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"hello",
		"mcp_custom_tool",
		{ path: "README.md", args: { secret: "x" } },
	);
	assert.equal(result, undefined);
	assert.equal(calls.length, 1);
	assert.deepEqual(calls[0].args.slice(0, 3), ["decide", "tool", "--json"]);
	const payload = JSON.parse(calls[0].args[3] as string) as { name: string };
	assert.deepEqual(payload, { name: "mcp_custom_tool" });
	assert.equal(isProtectedPiTool("mcp_custom_tool"), false);
	assert.equal(isProtectedPiTool("read"), true);
	assert.equal(isProtectedPiTool("write"), true);
	assert.match(piCoverageLabel(), /bash \+ write \+ edit \+ read policy-protected/);
	assert.match(piCoverageLabel(), /grep \+ find \+ ls root-preflight/);
	assert.match(piCoverageLabel(), /decide tool/);
	assert.match(piCoverageLabel(), /passthrough/);
	assert.equal(shouldNameGateTool("mcp_custom_tool"), true);
	assert.equal(shouldNameGateTool("contact_supervisor"), false);
	assert.equal(isPassthroughPiTool("intercom"), true);
	assert.equal(shouldNameGateTool("bash"), false);
});

test("Pi control-plane tools skip name-only decide (passthrough)", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([
		{ code: 0, stdout: decideAllowJson("tool") },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ cwd: process.cwd() });

	for (const tool of ["contact_supervisor", "intercom", "subagent"] as const) {
		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			tool,
			{ message: "hello" },
		);
		assert.equal(result, undefined, tool);
	}
	assert.equal(calls.length, 0, "passthrough tools must not spawn decide");
});

test("custom tool deny blocks with rule id on card", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([
		{ code: 3, stdout: decideBlockJson("tools.deny[0]", "tool") },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ cwd: process.cwd() });

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"read_file",
		{ uri: "file:///etc/passwd" },
	);

	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /rule tools\.deny\[0\]/);
	assert.equal(calls.length, 1);
	assert.deepEqual(calls[0].args.slice(0, 3), ["decide", "tool", "--json"]);
	const payload = JSON.parse(calls[0].args[3] as string) as { name: string };
	assert.deepEqual(payload, { name: "read_file" });
});

test("custom tool unavailable fails closed", async () => {
	const { pi, handlers } = makePi();
	const missing = { error: new Error("ENOENT") };
	const { spawn } = makeSpawn([missing, missing]);
	installRykExtension(pi, { spawn, rykBin: "missing-orca" });
	const { ctx } = makeCtx({ hasUI: false, mode: "print" });

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"mcp_custom_tool",
		{},
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /ryk is unavailable|spawn_failed/i);
});

test("session bypass skips decide tool for custom tools", async () => {
	const { pi, handlers, commands } = makePi();
	const { spawn, calls } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();
	await commands.get("ryk-stop")!.handler("", ctx);

	const first = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"mcp_custom_tool",
		{},
	);
	const second = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"mcp_custom_tool",
		{},
	);
	assert.equal(first, undefined);
	assert.equal(second, undefined);
	assert.equal(calls.length, 0);
});

test("empty custom tool name fails closed without spawning decide", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"   ",
		{},
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /missing non-empty tool name|malformed/i);
	assert.equal(calls.length, 0);
});

test("buildDecideToolPayload trims name", () => {
	assert.deepEqual(buildDecideToolPayload({ name: "  read_file  " }), {
		name: "read_file",
	});
});

test("runRykDecideTool maps block to deny and validates exit codes", async () => {
	const blocked = await runRykDecideTool(
		{ name: "read_file" },
		{
			spawn: makeSpawn([
				{ code: 3, stdout: decideBlockJson("tools.deny[1]", "tool") },
			]).spawn,
			rykBin: "ryk",
			timeoutMs: 1_000,
			cwd: process.cwd(),
		},
	);
	assert.equal(blocked.kind, "deny");

	for (const plan of [
		{ code: 1, stdout: decideAllowJson("tool") },
		{ code: 0, stdout: decideBlockJson("tools.deny[0]", "tool") },
		{ code: 0, stdout: "" },
	]) {
		// Two identical plans: protocol path retries once, still fail-closed.
		const result = await runRykDecideTool(
			{ name: "x" },
			{
				spawn: makeSpawn([plan, plan]).spawn,
				rykBin: "ryk",
				timeoutMs: 1_000,
				cwd: process.cwd(),
			},
		);
		assert.equal(result.kind, "error", JSON.stringify(plan));
		if (result.kind === "error") {
			assert.match(result.reason, /\[[a-z_]+\]/);
			assert.ok(result.failureClass);
		}
	}
});

test("runRykDecideTool retries once on malformed JSON then fail-closes", async () => {
	const bad = { code: 0, stdout: "{not-json" as string };
	const { spawn, calls } = makeSpawn([bad, bad]);
	const result = await runRykDecideTool(
		{ name: "x" },
		{ spawn, rykBin: "ryk", timeoutMs: 1_000, cwd: process.cwd() },
	);
	assert.equal(result.kind, "error");
	assert.equal(calls.length, 2);
	if (result.kind === "error") {
		assert.equal(result.failureClass, "malformed_json");
		assert.match(result.reason, /\[malformed_json\]/);
		assert.match(result.reason, /exit 0/);
		assert.match(result.reason, /stdout "\{not-json"/);
		assert.match(result.reason, /stderr empty/);
	}
});

test("formatMalformedJsonDetail includes exit and stream previews", () => {
	assert.equal(previewProcessOutput(""), "empty");
	assert.equal(previewProcessOutput("  hi  "), '"hi"');
	const detail = formatMalformedJsonDetail(
		{ code: 2, stdout: "", stderr: "ryk decide: --json requires a value.\n" },
		"decide",
	);
	assert.match(detail, /exit 2/);
	assert.match(detail, /stdout empty/);
	assert.match(detail, /--json requires a value/);
});

test("runRykDecideTool recovers when second attempt succeeds", async () => {
	const { spawn, calls } = makeSpawn([
		{ code: 0, stdout: "{not-json" },
		{ code: 0, stdout: decideAllowJson("tool") },
	]);
	const result = await runRykDecideTool(
		{ name: "x" },
		{ spawn, rykBin: "ryk", timeoutMs: 1_000, cwd: process.cwd() },
	);
	assert.equal(result.kind, "allow");
	assert.equal(calls.length, 2);
});

test("formatProtocolErrorReason includes class token", () => {
	const reason = formatProtocolErrorReason("timeout", "ryk decide timed out.");
	assert.equal(protocolFailureClassFromReason(reason), "timeout");
	assert.match(reason, /\[timeout\]/);
});

test("isTransientProtocolFailure covers spawn/json glitches only", () => {
	assert.equal(isTransientProtocolFailure("timeout"), true);
	assert.equal(isTransientProtocolFailure("malformed_json"), true);
	assert.equal(isTransientProtocolFailure("spawn_failed"), true);
	assert.equal(isTransientProtocolFailure("output_too_large"), true);
	assert.equal(isTransientProtocolFailure("inconsistent_exit"), true);
	assert.equal(isTransientProtocolFailure("unexpected"), false);
	assert.equal(isTransientProtocolFailure(undefined), false);
	assert.equal(allowWithWarningPermitsProtocolClass("spawn_failed"), true);
	assert.equal(allowWithWarningPermitsProtocolClass("timeout"), false);
	assert.equal(allowWithWarningPermitsProtocolClass("malformed_json"), false);
	assert.equal(allowWithWarningPermitsProtocolClass("unexpected"), false);
});

test("runRykDecideTool does not retry non-transient decision error", async () => {
	const err = {
		code: 1,
		stdout: JSON.stringify({
			decision: "error",
			reason: "ryk decide: evaluation failed; fail closed.",
			error_code: "evaluation_failed",
		}),
	};
	const { spawn, calls } = makeSpawn([err, err]);
	const result = await runRykDecideTool(
		{ name: "x" },
		{ spawn, rykBin: "ryk", timeoutMs: 1_000, cwd: process.cwd() },
	);
	assert.equal(result.kind, "error");
	assert.equal(calls.length, 1);
	if (result.kind === "error") {
		assert.equal(result.failureClass, "unexpected");
	}
});

test("write tool is evaluated via ryk decide file", async () => {
	const { pi, handlers, messages } = makePi();
	const { spawn, calls } = makeSpawn([
		{ code: 3, stdout: decideBlockJson("files.write.deny[2]") },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ cwd: process.cwd() });

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"write",
		{ path: ".ryk/policy.yaml", content: "evil" },
	);

	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /write action|blocked/i);
	assert.match(result?.reason ?? "", /rule files\.write\.deny\[2\]/);
	assert.equal(calls.length, 1);
	assert.deepEqual(calls[0].args.slice(0, 3), ["decide", "file", "--json"]);
	const payload = JSON.parse(calls[0].args[3] as string) as {
		path: string;
		operation: string;
	};
	assert.equal(payload.operation, "write");
	assert.ok(payload.path.includes(".ryk/policy.yaml"));
	assert.equal(messages.length, 1);
	assert.equal(messages[0].message.customType, "rykanv-decision");
	assert.match(messages[0].message.content, /Meta\s+files\.write\.deny\[2\]/);
});

test("edit tool allow proceeds without block", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([{ code: 0, stdout: decideAllowJson() }]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"edit",
		{ path: "src/main.ts", edits: [{ oldText: "a", newText: "b" }] },
	);
	assert.equal(result, undefined);
	assert.equal(calls[0].args[0], "decide");
	assert.equal(calls[0].args[1], "file");
});

test("read tool is evaluated via ryk decide file with operation read", async () => {
	const { pi, handlers, messages } = makePi();
	const { spawn, calls } = makeSpawn([
		{
			code: 3,
			stdout: decideBlockJson("files.read.deny[0]", "file.read"),
		},
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ cwd: process.cwd() });

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"read",
		{ path: ".ssh/id_rsa" },
	);

	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /read action|blocked/i);
	assert.match(result?.reason ?? "", /rule files\.read\.deny\[0\]/);
	assert.equal(calls.length, 1);
	assert.deepEqual(calls[0].args.slice(0, 3), ["decide", "file", "--json"]);
	const payload = JSON.parse(calls[0].args[3] as string) as {
		path: string;
		operation: string;
	};
	assert.equal(payload.operation, "read");
	assert.ok(payload.path.includes(".ssh/id_rsa"));
	assert.equal(messages.length, 1);
	assert.match(messages[0].message.content, /Meta\s+files\.read\.deny\[0\]/);
});

test("grep tool still evaluates .env path via decide file", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([
		{ code: 0, stdout: decideAllowJson("file.read") },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ cwd: process.cwd(), hasUI: false, mode: "print" });

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"grep",
		{ pattern: "secret", path: ".env" },
	);
	assert.equal(result, undefined);
	const payload = JSON.parse(calls[0].args[3] as string) as {
		path: string;
		operation: string;
	};
	assert.equal(payload.operation, "read");
	assert.ok(payload.path.includes(".env"));
});

test("find tool defaults missing path to cwd for decide file", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([
		{ code: 0, stdout: decideAllowJson("file.read") },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const cwd = process.cwd();
	const { ctx } = makeCtx({ cwd, hasUI: false, mode: "print" });

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"find",
		{ pattern: "**/*.pem" },
	);
	assert.equal(result, undefined);
	const payload = JSON.parse(calls[0].args[3] as string) as {
		path: string;
		operation: string;
	};
	assert.equal(payload.operation, "read");
	assert.equal(payload.path, cwd);
});

test("ls tool denies sensitive directory via decide file read", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn([
		{
			code: 3,
			stdout: decideBlockJson("files.read.deny[1]", "file.read"),
		},
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"ls",
		{ path: "~/.ssh" },
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /ls action|blocked/i);
	assert.match(result?.reason ?? "", /rule files\.read\.deny\[1\]/);
	const payload = JSON.parse(calls[0].args[3] as string) as {
		operation: string;
	};
	assert.equal(payload.operation, "read");
});

test("file-policy residual ask is permit without a prompt", async () => {
	await withClearedUnattendedEnv(async () => {
		const { pi, handlers } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		const { ctx } = makeCtx();
		let offered: string[] = [];
		(ctx.ui as any).select = async (_title: string, options: string[]) => {
			offered = options;
			return "Block";
		};

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined);
		assert.equal(offered.length, 0);
	});
});

test("staged file write is not permit on attended Pi", async () => {
	const { pi, handlers } = makePi();
	const { spawn } = makeSpawn([
		{ code: 7, stdout: decideJson("stage", "file.write") },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();
	let offered: string[] = [];
	(ctx.ui as any).select = async (_title: string, options: string[]) => {
		offered = options;
		return "Block";
	};

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"write",
		{ path: "src/main.ts", content: "x" },
	);
	assert.equal(result?.block, true);
	assert.equal(offered.length, 0);
});

test("allowOnceBypassEnabled honors env and strict mode", () => {
	assert.equal(allowOnceBypassEnabled({}), true);
	assert.equal(allowOnceBypassEnabled({}, "auto"), true);
	assert.equal(allowOnceBypassEnabled({}, "strict"), false);
	assert.equal(
		allowOnceBypassEnabled({ RYK_PI_ALLOW_ONCE: "false" }, "auto"),
		false,
	);
	assert.equal(
		allowOnceBypassEnabled({ RYK_PI_ALLOW_ONCE: "true" }, "strict"),
		true,
	);
	assert.deepEqual(askOptionsFor("policy", false), [
		"Deny",
		SESSION_GRANT_OPTION,
		"Disable Rykan V for this session",
		"Show why",
	]);
	// Policy: once first, then deny.
	assert.deepEqual(askOptionsFor("policy", true).slice(0, 2), [
		"Allow once",
		"Deny",
	]);
	// Protocol: session allow, once, deny (no doctor option).
	assert.deepEqual(askOptionsFor("unavailable", true), [
		"Allow for this session",
		"Allow once",
		"Deny",
	]);
	assert.ok(askOptionsFor("unavailable", true).includes("Allow once"));
	assert.ok(!askOptionsFor("unavailable", false).includes("Allow once"));
	assert.deepEqual(askOptionsFor("unavailable", false), [
		"Allow for this session",
		"Deny",
	]);
	assert.ok(
		!askOptionsFor("unavailable", true).some((o) => /doctor|repair/i.test(o)),
	);
});

test("strict mode residual ask is permit without a prompt", async () => {
	await withClearedUnattendedEnv(async () => {
		const { pi, handlers, commands } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		const { ctx } = makeCtx();
		await commands.get("ryk-mode")!.handler("strict", ctx);
		let offered: string[] = [];
		(ctx.ui as any).select = async (_title: string, options: string[]) => {
			offered = options;
			return "Block";
		};

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined);
		assert.equal(offered.length, 0);
	});
});

test("residual ask does not open once-bypass UI", async () => {
	await withClearedUnattendedEnv(async () => {
		const { pi, handlers, messages } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		const syntheticSecret = "AKIASYNTHETICONLY1234";
		const encodedSecret = "dG9rZW49c3ludGhldGljLW9ubHktc2VjcmV0";
		const { ctx, notifications } = makeCtx({
			cwd: `/tmp/${syntheticSecret}/${encodedSecret}`,
			sessionManager: { getSessionId: () => `session-${syntheticSecret}-${encodedSecret}` },
		});
		(ctx.ui as any).select = async () => "Allow once";

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined);
		assert.equal(
			messages.find((m) => m.message.customType === "ryk.audit"),
			undefined,
		);
	});
});

test("residual ask still permits when transcript auditing is unavailable", async () => {
	await withClearedUnattendedEnv(async () => {
		const { pi, handlers, messages } = makePi();
		delete (pi as { sendMessage?: unknown }).sendMessage;
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		const { ctx, notifications } = makeCtx();
		(ctx.ui as any).select = async () => "Allow once";

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined);
		assert.equal(messages.length, 0);
	});
});

test("isSubagentSession and shouldAutoDenyPolicyAsk helpers", () => {
	assert.equal(isSubagentSession({}), false);
	assert.equal(isSubagentSession({ PI_SUBAGENT_PARENT_SESSION: "" }), false);
	assert.equal(isSubagentSession({ PI_SUBAGENT_PARENT_SESSION: "   " }), false);
	assert.equal(
		isSubagentSession({ PI_SUBAGENT_PARENT_SESSION: "parent-session-1" }),
		true,
	);

	assert.equal(
		shouldAutoDenyPolicyAsk({ hasUI: true, mode: "tui" }, {}),
		false,
	);
	assert.equal(shouldAutoDenyPolicyAsk({ hasUI: false }, {}), false);
	assert.equal(
		shouldAutoDenyPolicyAsk({ hasUI: true, mode: "print" }, {}),
		false,
	);
	assert.equal(
		shouldAutoDenyPolicyAsk({ hasUI: true, mode: "json" }, {}),
		false,
	);
	assert.equal(
		shouldAutoDenyPolicyAsk({ hasUI: true, mode: "noninteractive" }, {}),
		false,
	);
	assert.equal(
		shouldAutoDenyPolicyAsk({ hasUI: false }, { RYK_UNATTENDED: "1" }),
		true,
	);
	assert.equal(
		shouldAutoDenyPolicyAsk({ hasUI: true, mode: "tui" }, { CI: "1" }),
		true,
	);
	assert.equal(
		shouldAutoDenyPolicyAsk({ hasUI: true, mode: "tui" }, { RYK_CI: "1" }),
		true,
	);
	assert.equal(
		shouldAutoDenyPolicyAsk({ hasUI: true, mode: "tui" }, { RYK_NONINTERACTIVE: "1" }),
		true,
	);
	assert.equal(
		shouldAutoDenyPolicyAsk({ hasUI: true, mode: "tui" }, { CI: "0" }),
		false,
	);
	assert.equal(
		shouldAutoDenyPolicyAsk(
			{ hasUI: true, mode: "tui" },
			{ PI_SUBAGENT_PARENT_SESSION: "parent-1" },
		),
		false,
	);
	assert.equal(
		shouldLocalSelectPolicyAsk({ hasUI: true, mode: "tui" }, {}),
		true,
	);
	assert.equal(
		shouldLocalSelectPolicyAsk(
			{ hasUI: true, mode: "tui" },
			{ PI_SUBAGENT_PARENT_SESSION: "parent-1" },
		),
		false,
	);
});

test("buildAutoDenyCopy locks Why/Next product voice", () => {
	const sub = buildAutoDenyCopy("subagent", "needs approval for write", "write");
	assert.equal(sub.title, DISPLAY_BRAND);
	assert.match(sub.summary, new RegExp(PRODUCT_NAME));
	assert.match(sub.summary, /can't prompt \(subagent\)/);
	assert.match(sub.nextStep, /parent Pi session/);
	assert.match(sub.nextStep, /mcp\.allow/);
	assert.equal(sub.rule, "rykanv:ask-no-ui");
	assert.match(sub.reason, /auto-denied \(subagent\)/);

	const non = buildAutoDenyCopy(
		"non-interactive",
		"needs approval",
		"bash",
		{ rule: "rykanv:parent-ask-timeout" },
	);
	assert.match(non.summary, /non-interactive/);
	assert.match(non.nextStep, /interactive Pi/);
	assert.equal(non.rule, "rykanv:parent-ask-timeout");
});

test("askOptionsFor policy includes session grant option", () => {
	const opts = askOptionsFor("policy", true);
	assert.ok(opts.includes(SESSION_GRANT_OPTION));
	assert.ok(opts.includes("Allow once"));
	const noOnce = askOptionsFor("policy", false);
	assert.ok(!noOnce.includes("Allow once"));
	assert.ok(noOnce.includes(SESSION_GRANT_OPTION));
});

test("policy ask permits noninteractive sessions so agents can work", async () => {
	await withClearedUnattendedEnv(async () => {
		const { pi, handlers, messages } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		const { ctx } = makeCtx({ hasUI: false, mode: "print" });
		let selectCalled = false;
		(ctx.ui as any).select = async () => {
			selectCalled = true;
			return "Allow once";
		};

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined);
		assert.equal(selectCalled, false, "select must not be called for residual ask");
		assert.equal(
			messages.find((m) => m.message.customType === "ryk.audit"),
			undefined,
		);
	});
});

test("policy ask auto-denies when RYK_UNATTENDED is set", async () => {
	await withClearedUnattendedEnv(async () => {
	const previous = process.env.RYK_UNATTENDED;
	process.env.RYK_UNATTENDED = "1";
	try {
		const { pi, handlers, messages } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		const { ctx } = makeCtx({ hasUI: false, mode: "print" });
		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result?.block, true);
		assert.match(result?.reason ?? "", /auto-denied/i);
		const audit = messages.find((m) => m.message.customType === "ryk.audit");
		assert.equal(
			(audit?.message.details as { event?: string } | undefined)?.event,
			"ryk_ask_auto_deny",
		);
	} finally {
		if (previous === undefined) delete process.env.RYK_UNATTENDED;
		else process.env.RYK_UNATTENDED = previous;
	}
	});
});

test("policy ask permits print mode even when hasUI is true", async () => {
	await withClearedUnattendedEnv(async () => {
		const { pi, handlers } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		const { ctx } = makeCtx({ hasUI: true, mode: "print" });
		let selectCalled = false;
		(ctx.ui as any).select = async () => {
			selectCalled = true;
			return "Allow once";
		};

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined);
		assert.equal(selectCalled, false);
	});
});

test("policy ask subagent permits residual ask without parent wait", async () => {
	await withClearedUnattendedEnv(async () => {
	const previous = process.env.PI_SUBAGENT_PARENT_SESSION;
	const previousTimeout = process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS;
	const previousRoot = process.env.RYK_PI_ASK_ROOT;
	const askRoot = mkdtempSync(resolve(tmpdir(), "ryk-pi-ask-"));
	process.env.PI_SUBAGENT_PARENT_SESSION = "parent-session-stress";
	process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS = "500";
	process.env.RYK_PI_ASK_ROOT = askRoot;
	let clock = 0;
	try {
		const { pi, handlers, messages } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		installRykExtension(pi, {
			spawn,
			rykBin: "ryk",
			piAskRoot: askRoot,
			parentAskPollMs: 0,
			now: () => clock,
			sleep: async (ms) => {
				clock += ms;
			},
		});
		const { ctx } = makeCtx({ hasUI: true, mode: "tui" });
		let selectCalled = false;
		(ctx.ui as any).select = async () => {
			selectCalled = true;
			return "Allow once";
		};

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined);
		assert.equal(
			selectCalled,
			false,
			"subagent must not local-select even with hasUI",
		);
	} finally {
		if (previous === undefined) delete process.env.PI_SUBAGENT_PARENT_SESSION;
		else process.env.PI_SUBAGENT_PARENT_SESSION = previous;
		if (previousTimeout === undefined)
			delete process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS;
		else process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS = previousTimeout;
		if (previousRoot === undefined) delete process.env.RYK_PI_ASK_ROOT;
		else process.env.RYK_PI_ASK_ROOT = previousRoot;
		rmSync(askRoot, { recursive: true, force: true });
	}
	});
});

test("policy ask subagent permits residual ask without parent IPC", async () => {
	await withClearedUnattendedEnv(async () => {
	const previous = process.env.PI_SUBAGENT_PARENT_SESSION;
	const previousTimeout = process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS;
	const previousRoot = process.env.RYK_PI_ASK_ROOT;
	const askRoot = mkdtempSync(resolve(tmpdir(), "ryk-pi-ask-"));
	const parentId = "parent-session-forward";
	process.env.PI_SUBAGENT_PARENT_SESSION = parentId;
	process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS = "2000";
	process.env.RYK_PI_ASK_ROOT = askRoot;
	let clock = 0;
	try {
		const { pi, handlers, messages } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
	installRykExtension(pi, {
			spawn,
			rykBin: "ryk",
			piAskRoot: askRoot,
			parentAskPollMs: 0,
			now: () => clock,
			sleep: async (ms) => {
				// First poll: answer any pending request from parent side.
				const dir = parentAskDir(askRoot, parentId);
				const pending = listPendingRequests(dir);
				for (const req of pending) {
					writeAskResponse(dir, {
						v: 1,
						id: req.id,
						choice: "run_once",
						decided_at_ms: clock,
					});
				}
				clock += ms;
			},
		});
		const { ctx } = makeCtx({ hasUI: true, mode: "tui" });
		(ctx.ui as any).select = async () => {
			throw new Error("child must not call select");
		};

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined, "residual ask is permit");
	} finally {
		if (previous === undefined) delete process.env.PI_SUBAGENT_PARENT_SESSION;
		else process.env.PI_SUBAGENT_PARENT_SESSION = previous;
		if (previousTimeout === undefined)
			delete process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS;
		else process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS = previousTimeout;
		if (previousRoot === undefined) delete process.env.RYK_PI_ASK_ROOT;
		else process.env.RYK_PI_ASK_ROOT = previousRoot;
		rmSync(askRoot, { recursive: true, force: true });
	}
	});
});

test("policy ask subagent does not wait for a parent block", async () => {
	await withClearedUnattendedEnv(async () => {
	const previous = process.env.PI_SUBAGENT_PARENT_SESSION;
	const previousTimeout = process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS;
	const previousRoot = process.env.RYK_PI_ASK_ROOT;
	const askRoot = mkdtempSync(resolve(tmpdir(), "ryk-pi-ask-"));
	const parentId = "parent-session-block";
	process.env.PI_SUBAGENT_PARENT_SESSION = parentId;
	process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS = "2000";
	process.env.RYK_PI_ASK_ROOT = askRoot;
	let clock = 0;
	try {
		const { pi, handlers } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, {
			spawn,
			rykBin: "ryk",
			piAskRoot: askRoot,
			parentAskPollMs: 0,
			now: () => clock,
			sleep: async (ms) => {
				const dir = parentAskDir(askRoot, parentId);
				for (const req of listPendingRequests(dir)) {
					writeAskResponse(dir, {
						v: 1,
						id: req.id,
						choice: "block",
						decided_at_ms: clock,
					});
				}
				clock += ms;
			},
		});
		const { ctx } = makeCtx({ hasUI: true, mode: "tui" });

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined);
	} finally {
		if (previous === undefined) delete process.env.PI_SUBAGENT_PARENT_SESSION;
		else process.env.PI_SUBAGENT_PARENT_SESSION = previous;
		if (previousTimeout === undefined)
			delete process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS;
		else process.env.RYK_PI_PARENT_ASK_TIMEOUT_MS = previousTimeout;
		if (previousRoot === undefined) delete process.env.RYK_PI_ASK_ROOT;
		else process.env.RYK_PI_ASK_ROOT = previousRoot;
		rmSync(askRoot, { recursive: true, force: true });
	}
	});
});

test("session grant short-circuits decide for granted tool name", async () => {
	const previousRoot = process.env.RYK_PI_ASK_ROOT;
	const askRoot = mkdtempSync(resolve(tmpdir(), "ryk-pi-ask-"));
	process.env.RYK_PI_ASK_ROOT = askRoot;
	try {
		const sessionId = "session-grant-main";
		const dir = parentAskDir(askRoot, sessionId);
		addSessionGrant(dir, "ctx_batch_execute", Date.now());
		assert.equal(hasSessionGrant(dir, "ctx_batch_execute"), true);

		const { pi, handlers, messages } = makePi();
		const { spawn, calls } = makeSpawn();
		installRykExtension(pi, {
			spawn,
			rykBin: "ryk",
			piAskRoot: askRoot,
			parentAskPollMs: 0,
		});
		const { ctx } = makeCtx({
			hasUI: true,
			mode: "tui",
			sessionManager: { getSessionId: () => sessionId },
		});

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"ctx_batch_execute",
			{ query: "x" },
		);
		assert.equal(result, undefined, "grant hit must allow");
		assert.equal(calls.length, 0, "grant hit must skip decide spawn");
		const grantAudit = messages.find(
			(m) =>
				(m.message.details as { event?: string } | undefined)?.event ===
				"ryk_session_grant_hit",
		);
		assert.ok(grantAudit, "expected ryk_session_grant_hit audit");
	} finally {
		if (previousRoot === undefined) delete process.env.RYK_PI_ASK_ROOT;
		else process.env.RYK_PI_ASK_ROOT = previousRoot;
		rmSync(askRoot, { recursive: true, force: true });
	}
});

test("parent main session answers pending child ask via select", async () => {
	const previousRoot = process.env.RYK_PI_ASK_ROOT;
	const previousParent = process.env.PI_SUBAGENT_PARENT_SESSION;
	const askRoot = mkdtempSync(resolve(tmpdir(), "ryk-pi-ask-"));
	process.env.RYK_PI_ASK_ROOT = askRoot;
	delete process.env.PI_SUBAGENT_PARENT_SESSION;
	const parentId = "parent-poll-session";
	try {
		const dir = parentAskDir(askRoot, parentId);
		// Seed a pending child request.
		writeAskRequest(dir, {
			v: 1,
			id: "req-test-1",
			parent_session: parentId,
			tool: "write",
			reason: "needs approval",
			command_or_name: "src/main.ts",
			created_at_ms: 1,
			timeout_ms: 60_000,
		});

		const { pi, handlers, messages } = makePi();
		const { spawn } = makeSpawn([
			{ code: 0, stdout: decideAllowJson("file.write") },
		]);
		installRykExtension(pi, {
			spawn,
			rykBin: "ryk",
			piAskRoot: askRoot,
			parentAskPollMs: 0,
			now: () => 100,
		});
		const { ctx, selections } = makeCtx({
			hasUI: true,
			mode: "tui",
			sessionManager: { getSessionId: () => parentId },
		});
		selections.push("Block");

		// Fire any tool call so parent poll drains pending asks.
		await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "ok.ts", content: "y" },
		);

		const resPath = resolve(dir, "res-req-test-1.json");
		const res = JSON.parse(readFileSync(resPath, "utf8")) as {
			choice: string;
			id: string;
		};
		assert.equal(res.id, "req-test-1");
		assert.equal(res.choice, "block");
		const parentAudit = messages.find(
			(m) =>
				(m.message.details as { event?: string } | undefined)?.event ===
				"ryk_parent_ask_response",
		);
		assert.ok(parentAudit, "expected parent ask response audit");
	} finally {
		if (previousRoot === undefined) delete process.env.RYK_PI_ASK_ROOT;
		else process.env.RYK_PI_ASK_ROOT = previousRoot;
		if (previousParent === undefined)
			delete process.env.PI_SUBAGENT_PARENT_SESSION;
		else process.env.PI_SUBAGENT_PARENT_SESSION = previousParent;
		rmSync(askRoot, { recursive: true, force: true });
	}
});

test("policy ask permits residual ask in interactive parent TUI", async () => {
	await withClearedUnattendedEnv(async () => {
		const previous = process.env.PI_SUBAGENT_PARENT_SESSION;
		delete process.env.PI_SUBAGENT_PARENT_SESSION;
		try {
			const { pi, handlers } = makePi();
			const { spawn } = makeSpawn([
				{ code: 7, stdout: decideJson("ask", "file.write") },
			]);
			installRykExtension(pi, { spawn, rykBin: "ryk" });
			const { ctx } = makeCtx({ hasUI: true, mode: "tui" });
			let selectCalled = false;
			(ctx.ui as any).select = async () => {
				selectCalled = true;
				return "Block";
			};

			const result = await fireToolCall(
				handlers.get("tool_call")![0],
				ctx,
				"",
				"write",
				{ path: "src/main.ts", content: "x" },
			);
			assert.equal(result, undefined);
			assert.equal(selectCalled, false, "residual ask must not prompt");
		} finally {
			if (previous === undefined) delete process.env.PI_SUBAGENT_PARENT_SESSION;
			else process.env.PI_SUBAGENT_PARENT_SESSION = previous;
		}
	});
});

test("policy ask auto-deny still blocks when audit is unavailable", async () => {
	await withClearedUnattendedEnv(async () => {
	const previous = process.env.RYK_UNATTENDED;
	process.env.RYK_UNATTENDED = "1";
	try {
		const { pi, handlers, messages } = makePi();
		delete (pi as { sendMessage?: unknown }).sendMessage;
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		const { ctx } = makeCtx({ hasUI: false, mode: "print" });
		let selectCalled = false;
		(ctx.ui as any).select = async () => {
			selectCalled = true;
			return "Allow once";
		};

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result?.block, true);
		assert.equal(selectCalled, false);
		assert.match(result?.reason ?? "", /auto-denied/i);
		assert.equal(messages.length, 0);
	} finally {
		if (previous === undefined) delete process.env.RYK_UNATTENDED;
		else process.env.RYK_UNATTENDED = previous;
	}
	});
});

test("bash policy ask permits noninteractive sessions", async () => {
	await withClearedUnattendedEnv(async () => {
		const { pi, handlers } = makePi();
		const { spawn } = makeSpawn([{ code: 0, stdout: askJson() }]);
		installRykExtension(pi, { spawn, rykBin: "ryk" });
		const { ctx } = makeCtx({ hasUI: false, mode: "print" });
		let selectCalled = false;
		(ctx.ui as any).select = async () => {
			selectCalled = true;
			return "Allow once";
		};

		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"git push --force",
		);
		assert.equal(result, undefined);
		assert.equal(selectCalled, false);
	});
});

test("interactive policy ask permits residual ask without select", async () => {
	await withClearedUnattendedEnv(async () => {
		const previous = process.env.PI_SUBAGENT_PARENT_SESSION;
		delete process.env.PI_SUBAGENT_PARENT_SESSION;
		try {
			const { pi, handlers } = makePi();
			const { spawn } = makeSpawn([
				{ code: 7, stdout: decideJson("ask", "file.write") },
			]);
			installRykExtension(pi, { spawn, rykBin: "ryk" });
			const { ctx } = makeCtx({ hasUI: true, mode: "tui" });
			(ctx.ui as any).select = async () => undefined;

			const result = await fireToolCall(
				handlers.get("tool_call")![0],
				ctx,
				"",
				"write",
				{ path: "src/main.ts", content: "x" },
			);
			assert.equal(result, undefined);
		} finally {
			if (previous === undefined) delete process.env.PI_SUBAGENT_PARENT_SESSION;
			else process.env.PI_SUBAGENT_PARENT_SESSION = previous;
		}
	});
});

test("malformed read tool call fails closed", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"read",
		{ path: "   " },
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /malformed Pi read tool call/);
	assert.equal(calls.length, 0);
});

test("read tool unavailable path fails closed in noninteractive mode", async () => {
	const { pi, handlers } = makePi();
	const missing = { error: new Error("spawn ENOENT") };
	const { spawn } = makeSpawn([missing, missing]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ hasUI: false, mode: "print" });

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"read",
		{ path: "README.md" },
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /ryk is unavailable|could not evaluate this read|spawn_failed/i);
});

test("session bypass skips write and read evaluation", async () => {
	const { pi, handlers, commands } = makePi();
	const { spawn, calls } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx, notifications } = makeCtx();

	await commands.get("ryk-stop")!.handler("", ctx);
	const writeResult = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"write",
		{ path: "/tmp/x", content: "y" },
	);
	const readResult = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"",
		"read",
		{ path: "/tmp/secret" },
	);
	assert.equal(writeResult, undefined);
	assert.equal(readResult, undefined);
	assert.equal(calls.length, 0);
	assert.ok(
		notifications.some((n) => /write allowed without ryk/i.test(n.message)),
	);
	assert.ok(
		notifications.some((n) => /read allowed without ryk/i.test(n.message)),
	);
});

test("buildDecideFilePayload, resolveToolPath, extractDecideFilePath", () => {
	const payload = buildDecideFilePayload("/tmp/a", "write");
	assert.deepEqual(payload, { path: "/tmp/a", operation: "write" });
	assert.deepEqual(buildDecideFilePayload("/tmp/b", "read"), {
		path: "/tmp/b",
		operation: "read",
	});
	const { ctx } = makeCtx({ cwd: "/workspace" });
	assert.equal(resolveToolPath("/abs/file", ctx), "/abs/file");
	assert.equal(resolveToolPath("/workspace/src/../.env", ctx), "/workspace/.env");
	assert.equal(
		resolveToolPath("rel.txt", { cwd: process.cwd() }),
		resolve(process.cwd(), "rel.txt"),
	);
	assert.deepEqual(extractDecideFilePath("read", { path: "a.txt" }), {
		path: "a.txt",
		required: true,
	});
	assert.deepEqual(extractDecideFilePath("grep", { pattern: "x" }), {
		path: ".",
		required: false,
	});
	assert.deepEqual(extractDecideFilePath("find", { pattern: "*", path: "src" }), {
		path: "src",
		required: false,
	});
	assert.deepEqual(extractDecideFilePath("ls", {}), {
		path: ".",
		required: false,
	});
});

test("bash safe command with ryk allow returns undefined", async () => {
	const { pi, handlers } = makePi();
	const { spawn } = makeSpawn([{ code: 0, stdout: allowJson() }]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"git status",
	);
	assert.equal(result, undefined);
});

test("bash dangerous command with ryk deny returns block", async () => {
	const { pi, handlers, messages } = makePi();
	const { spawn } = makeSpawn([{ code: 2, stdout: denyJson() }]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx, widgets, notifications } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"rm -rf /",
	);
	assert.deepEqual(result, {
		block: true,
		reason:
			"Rykan V blocked this bash command: destructive filesystem command • rule core.filesystem:destructive-rm",
	});
	assert.equal(messages.length, 1);
	assert.equal(messages[0].message.customType, "rykanv-decision");
	assert.equal(messages[0].message.display, true);
	assert.deepEqual(messages[0].options, { triggerTurn: false });
	assert.equal(
		widgets.some((entry) => entry.key === "rykanv-block" && entry.value !== undefined),
		false,
		"expected deny output to avoid the docked widget surface",
	);
	// Hard deny also flashes a best-effort error notify (card remains primary).
	assert.equal(notifications.length, 1, "hard deny should notify once");
	assert.equal(notifications[0]?.type, "error");
	assert.match(notifications[0]?.message ?? "", /blocked this bash command/i);
	assert.ok(
		!notifications[0]?.message.includes("\n"),
		"notify text should be single-line",
	);
	assert.ok(
		!/Recourse:/i.test(notifications[0]?.message ?? ""),
		"notify must not embed Recourse walls",
	);
	const inlineDecision = messages[0].message.content;
	assert.match(inlineDecision, /RYKAN V · Blocked/);
	assert.ok(
		!/[┏┓┗┛┃━┌┐└┘│─]/.test(inlineDecision),
		"decision card must not use ASCII/Unicode box frames",
	);
	assert.ok(
		!/COMMAND STOPPED BEFORE EXECUTION|YOUR CALL/.test(inlineDecision),
		"legacy state lines must be gone",
	);
	assert.match(inlineDecision, /destructive filesystem command/);
	assert.match(inlineDecision, /Why\s+destructive filesystem command/);
	assert.match(inlineDecision, /Cmd\s+rm -rf \//);
	assert.match(
		inlineDecision,
		/Meta\s+core\.filesystem:destructive-rm/,
	);
	assert.ok(
		inlineDecision.split("\n").every((line) => line.length <= 80),
		"expected a compact decision card",
	);
});

test("hard deny still blocks when ui.notify is missing", async () => {
	const { pi, handlers, messages } = makePi();
	const { spawn } = makeSpawn([{ code: 2, stdout: denyJson() }]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({
		ui: {
			// no notify — best-effort flash optional
			setStatus: () => {},
			setWidget: () => {},
			select: async () => undefined,
		},
	});

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"rm -rf /",
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /blocked this bash command/i);
	assert.equal(messages.length, 1, "decision card path still runs without notify");
	assert.equal(messages[0].message.customType, "rykanv-decision");
});

test("hard deny still blocks when ui.notify throws", async () => {
	const { pi, handlers, messages } = makePi();
	const { spawn } = makeSpawn([{ code: 2, stdout: denyJson() }]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({
		ui: {
			notify: () => {
				throw new Error("notify transport failed");
			},
			setStatus: () => {},
			setWidget: () => {},
			select: async () => undefined,
		},
	});

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"rm -rf /",
	);
	assert.equal(result?.block, true, "notify throw must not fail open");
	assert.match(result?.reason ?? "", /blocked this bash command/i);
	assert.equal(messages.length, 1);
});

test("hard deny notify is short/sanitized even when reason has Recourse wall", async () => {
	const { pi, handlers } = makePi();
	const { spawn } = makeSpawn([
		{
			code: 2,
			stdout: JSON.stringify({
				decision: "deny",
				reason:
					"destructive filesystem command\nRecourse: operator can run ryk allow-once ABC\nNext: ryk explain rm",
				rule_id: "core.filesystem:destructive-rm",
				daemon: { status: "healthy", compatible: true },
			}),
		},
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx, notifications } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"rm -rf /",
	);
	assert.equal(result?.block, true);
	assert.equal(notifications.length, 1);
	assert.equal(notifications[0]?.type, "error");
	const msg = notifications[0]?.message ?? "";
	assert.ok(!msg.includes("\n"), "notify collapsed to single line");
	// Prefer no Recourse wall in the flash; card remains the detail surface.
	assert.ok(
		!/Recourse:/i.test(msg),
		`notify should not re-surface Recourse wall, got: ${msg}`,
	);
	// Wall strip must run on the reason atom, not the composed sentence —
	// otherwise greedy Recourse:.*$ also drops rule/pack/severity suffix.
	assert.match(
		msg,
		/core\.filesystem:destructive-rm/,
		`notify should keep rule suffix after wall strip, got: ${msg}`,
	);
	assert.match(msg, /destructive filesystem command/i);
	// Agent block reason must also strip Recourse / allow-once codes.
	const agentReason = result?.reason ?? "";
	assert.ok(!agentReason.includes("\n"), "agent reason must be one line");
	assert.ok(
		!/Recourse:/i.test(agentReason),
		`agent reason must not contain Recourse:, got: ${agentReason}`,
	);
	assert.ok(
		!/allow-once\s+ABC/i.test(agentReason),
		`agent reason must not expose redeemable allow-once codes, got: ${agentReason}`,
	);
	assert.match(agentReason, /destructive filesystem command/i);
	assert.match(agentReason, /core\.filesystem:destructive-rm/);
});

test("hard deny with remediation puts short Next in agent reason and card", async () => {
	const { pi, handlers, messages } = makePi();
	const { spawn } = makeSpawn([
		{
			code: 2,
			stdout: JSON.stringify({
				decision: "deny",
				reason:
					"destructive filesystem command\nRecourse: operator can run ryk allow-once SECRET123\nNext: ignore this wall",
				rule_id: "core.filesystem:destructive-rm",
				remediation: [
					{ description: "Use a safer delete scoped to the project tree" },
				],
				daemon: { status: "healthy", compatible: true },
			}),
		},
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx, notifications } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"rm -rf /",
	);
	assert.equal(result?.block, true);
	const agentReason = result?.reason ?? "";
	assert.ok(!agentReason.includes("\n"), "agent reason must be single line");
	assert.match(agentReason, /destructive filesystem command/i);
	assert.match(agentReason, /rule core\.filesystem:destructive-rm/);
	assert.match(agentReason, /Next:/i);
	assert.match(agentReason, /safer delete|project tree/i);
	assert.ok(
		!/Recourse:/i.test(agentReason),
		`agent reason must not contain Recourse:, got: ${agentReason}`,
	);
	assert.ok(
		!/SECRET123|allow-once/i.test(agentReason),
		`agent reason must not expose allow-once codes, got: ${agentReason}`,
	);
	assert.ok(
		!/ignore this wall/i.test(agentReason),
		"agent Next must come from remediation, not CLI wall text",
	);
	// Exactly one Next clause.
	assert.equal(
		(agentReason.match(/Next:/gi) ?? []).length,
		1,
		`expected one Next clause, got: ${agentReason}`,
	);
	assert.ok(
		agentReason.length <= 320,
		`agent reason prefer ≤320 chars, got ${agentReason.length}`,
	);

	// Human card still rich with Next from remediation.
	const decision = messages.find(
		(m) => m.message.customType === "rykanv-decision",
	);
	const details = decision?.message.details as
		| { nextStep?: string; summary?: string; rule?: string }
		| undefined;
	assert.match(details?.nextStep ?? "", /safer delete|project tree/i);
	assert.match(decision?.message.content ?? "", /Next\s+/);

	// Notify stays short, no Recourse walls.
	assert.equal(notifications.length, 1);
	assert.ok(!/Recourse:/i.test(notifications[0]?.message ?? ""));
});

test("hard deny without remediation keeps non-empty agent reason without fake Next", async () => {
	const { pi, handlers, messages } = makePi();
	const { spawn } = makeSpawn([{ code: 2, stdout: denyJson() }]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"rm -rf /",
	);
	assert.equal(result?.block, true);
	const agentReason = result?.reason ?? "";
	assert.ok(agentReason.length > 0, "agent reason must be non-empty");
	assert.ok(!agentReason.includes("\n"));
	assert.match(agentReason, /blocked this bash command/i);
	assert.match(agentReason, /rule core\.filesystem:destructive-rm/);
	assert.ok(
		!/Next:/i.test(agentReason),
		`must not invent Next without remediation, got: ${agentReason}`,
	);
	const decision = messages.find(
		(m) => m.message.customType === "rykanv-decision",
	);
	const details = decision?.message.details as
		| { nextStep?: string }
		| undefined;
	assert.equal(details?.nextStep, undefined);
});

test("formatAgentBlockReason truncates long Next and never reintroduces Recourse", () => {
	const longNext = `Re-run with ${"x".repeat(200)} scoped path`;
	const reason = formatAgentBlockReason(
		{
			variant: "block",
			title: DISPLAY_BRAND,
			summary:
				"unsafe path write Recourse: ryk allow-once CODE99 Next: operator wall",
			rule: "files.write:deny",
			nextStep: longNext,
		},
		"write",
	);
	assert.ok(!reason.includes("\n"));
	assert.ok(!/Recourse:/i.test(reason));
	assert.ok(!/CODE99|allow-once/i.test(reason));
	assert.ok(!/operator wall/i.test(reason));
	assert.match(reason, /Next:/i);
	assert.match(reason, /rule files\.write:deny/);
	assert.ok(reason.length <= 320, `got length ${reason.length}: ${reason}`);
	const nextPart = reason.split(/Next:\s*/i)[1] ?? "";
	assert.ok(
		nextPart.length <= 120 + 3,
		`Next clause should be truncated (~120), got ${nextPart.length}`,
	);
	// Long Why must not erase reserved Next recovery clause or the rule atom.
	const longWhy = `unsafe-${"y".repeat(400)} path`;
	const preserved = formatAgentBlockReason(
		{
			variant: "block",
			title: DISPLAY_BRAND,
			summary: longWhy,
			rule: "files.write:deny",
			nextStep: "Use a project-scoped path",
		},
		"write",
	);
	assert.match(preserved, /Next:\s*Use a project-scoped path/i);
	assert.match(
		preserved,
		/rule files\.write:deny/,
		`long Why must not drop rule, got: ${preserved}`,
	);
	assert.ok(preserved.length <= 320);
	assert.ok(!/Recourse:/i.test(preserved));
});

test("formatAgentBlockReason auto-deny why is single-branded", () => {
	const reason = formatAgentBlockReason(
		{
			variant: "block",
			title: DISPLAY_BRAND,
			summary: "auto-denied (non-interactive): needs approval for write",
			rule: "rykanv:ask-no-ui",
			nextStep: "Re-run in interactive Pi, or pre-allow the tool in policy.",
		},
		"write",
	);
	assert.match(reason, /auto-denied \(non-interactive\)/i);
	assert.match(reason, /Next:/i);
	assert.match(reason, /rule rykanv:ask-no-ui/);
	// Only one product brand prefix (blocked verb), not "PRODUCT blocked: PRODUCT auto-denied".
	const productHits = (reason.match(new RegExp(PRODUCT_NAME, "gi")) ?? [])
		.length;
	assert.equal(
		productHits,
		1,
		`expected single ${PRODUCT_NAME} brand, got ${productHits}: ${reason}`,
	);
	assert.ok(reason.length <= 320);
});

test("formatAgentBlockReason does not include command preview", () => {
	const reason = formatAgentBlockReason(
		{
			variant: "block",
			title: DISPLAY_BRAND,
			summary: "destructive filesystem command",
			rule: "core.filesystem:destructive-rm",
			preview: "rm -rf /",
		},
		"bash",
	);
	assert.ok(!reason.includes("rm -rf /"), `preview leaked into agent reason: ${reason}`);
	assert.ok(!/\bCmd\b/.test(reason), `Cmd label leaked into agent reason: ${reason}`);
	assert.match(reason, /destructive filesystem command/);
	assert.match(reason, /rule core\.filesystem:destructive-rm/);
});

test("ryk inline decision wraps long reasons without a fixed box frame", async () => {
	const longReason = `unsafe-${"x".repeat(120)} command escaped policy`;
	const { pi, handlers, messages } = makePi();
	const { spawn } = makeSpawn([
		{
			code: 2,
			stdout: JSON.stringify({
				decision: "deny",
				reason: longReason,
				rule_id: "custom.long-reason",
			}),
		},
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();

	await fireToolCall(handlers.get("tool_call")![0], ctx, "dangerous-command");

	const inlineDecision = messages[0]?.message.content;
	assert.ok(inlineDecision, "expected inline ryk decision content");
	assert.ok(
		!/[┏┓┗┛┃━┌┐└┘│─]/.test(inlineDecision),
		"decision card must not use ASCII/Unicode box frames",
	);
	assert.ok(
		inlineDecision.split("\n").every((line) => line.length <= 80),
		"expected long-reason card lines to stay compact",
	);
	assert.match(inlineDecision, /Why\s+unsafe-/);
	assert.match(inlineDecision, /command escaped policy/);
});

test("bash dangerous command with ryk deny blocks even when exit code is not 2", async () => {
	const { pi, handlers } = makePi();
	const { spawn } = makeSpawn([{ code: 0, stdout: denyJson() }]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();

	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"rm -rf /",
	);
	assert.deepEqual(result, {
		block: true,
		reason:
			"Rykan V blocked this bash command: destructive filesystem command • rule core.filesystem:destructive-rm",
	});
});

test("ryk error in non-interactive mode blocks", async () => {
	const { pi, handlers } = makePi();
	const err = { code: 3 as number, stdout: errorJson() };
	const { spawn } = makeSpawn([err, err]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ hasUI: false, mode: "print" });

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result.block, true);
	assert.match(result.reason, /\/ryk-doctor|Fail-closed|malformed|unavailable|error/i);
});

test("ryk error in interactive mode fail-closes without a prompt", async () => {
	const { pi, handlers } = makePi();
	const err = { code: 3 as number, stdout: errorJson() };
	const { spawn } = makeSpawn([err, err]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();
	(ctx.ui as { select?: unknown }).select = async () => {
		throw new Error("protocol failure must not open a select()");
	};

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result.block, true);
	assert.match(result.reason, /\/ryk-doctor|Fail-closed|malformed|unavailable|error/i);
});

test("auto mode blocks print sessions even when hasUI is true", async () => {
	const { pi, handlers } = makePi();
	const err = { code: 3 as number, stdout: errorJson() };
	const { spawn } = makeSpawn([err, err]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ hasUI: true, mode: "print" });

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result.block, true);
	assert.match(result.reason, /\/ryk-doctor|Fail-closed|malformed|unavailable|error/i);
});

test("strict mode blocks", async () => {
	const { pi, handlers, commands } = makePi();
	const err = { code: 3 as number, stdout: errorJson() };
	const { spawn } = makeSpawn([err, err]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();
	await commands.get("ryk-mode")!.handler("strict", ctx);

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result.block, true);
});

test("allow-with-warning allows only spawn_failed unavailability", async () => {
	const { pi, handlers, commands } = makePi();
	const missing = { error: new Error("ENOENT") };
	// spawn_failed is transient → one retry, then allow-with-warning soft-allows.
	const { spawn } = makeSpawn([missing, missing]);
	installRykExtension(pi, { spawn, rykBin: "missing-orca" });
	const { ctx, notifications } = makeCtx();
	await commands.get("ryk-mode")!.handler("allow-with-warning", ctx);

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result, undefined);
	assert.equal(notifications.at(-1)?.type, "warning");
	assert.match(notifications.at(-1)?.message ?? "", /allowing bash with warning/i);
});

test("allow-with-warning still fail-closes on protocol decision error", async () => {
	const { pi, handlers, commands } = makePi();
	const err = { code: 3 as number, stdout: errorJson() };
	const { spawn, calls } = makeSpawn([err]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();
	await commands.get("ryk-mode")!.handler("allow-with-warning", ctx);

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /Failure class|unexpected|daemon/i);
	// Non-transient: single attempt.
	assert.equal(calls.length, 1);
});

test("malformed ryk JSON follows unavailable policy", async () => {
	const { pi, handlers } = makePi();
	// Retry once: both attempts malformed → still fail-closed with class token.
	const { spawn } = makeSpawn([
		{ code: 0, stdout: "{not-json" },
		{ code: 0, stdout: "{not-json" },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ hasUI: false, mode: "print" });

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result.block, true);
	assert.match(result.reason, /malformed JSON|malformed_json|Fail-closed/i);
	// Diagnostics must surface what the child actually emitted.
	assert.match(result.reason, /exit 0/);
	assert.match(result.reason, /\{not-json/);
});

test("repairMessage stays short enough for the ask card", () => {
	const long = formatProtocolErrorReason(
		"malformed_json",
		formatMalformedJsonDetail(
			{
				code: 0,
				stdout: "{not-json " + "x".repeat(200),
				stderr: "noise",
			},
			"evaluate",
		),
	);
	const card = repairMessage(long, "bash");
	assert.ok(card.length <= 220, card);
	assert.match(card, /Fail-closed/);
	assert.match(card, /\/ryk-doctor/);
	assert.doesNotMatch(card, /Coverage:/);
	assert.doesNotMatch(card, /not a permanent session brick/i);
});

test("protocol block choice sticks for the rest of the session", async () => {
	const { pi, handlers } = makePi();
	const bad = { code: 0 as number, stdout: "{not-json" };
	// Two tools × one retry each = 4 spawns if both go through evaluate; sticky may still evaluate.
	const { spawn, calls } = makeSpawn([bad, bad, bad, bad, bad, bad]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx, selections } = makeCtx();

	const first = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(first?.block, true);
	const selectsBefore = selections.length;

	const second = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"echo again",
	);
	assert.equal(second?.block, true);
	assert.equal(selections.length, selectsBefore, "no select on protocol failure");
	assert.ok(calls.length >= 2);
});

test("subagent protocol failure fail-closes without parent-forward ask", async () => {
	const previous = process.env.PI_SUBAGENT_PARENT_SESSION;
	const previousRoot = process.env.RYK_PI_ASK_ROOT;
	const askRoot = mkdtempSync(resolve(tmpdir(), "ryk-pi-proto-"));
	const parentId = "parent-proto-session";
	process.env.PI_SUBAGENT_PARENT_SESSION = parentId;
	process.env.RYK_PI_ASK_ROOT = askRoot;
	try {
		const { pi, handlers } = makePi();
		const bad = { code: 0 as number, stdout: "{not-json" };
		const { spawn } = makeSpawn([bad, bad]);
		installRykExtension(pi, {
			spawn,
			rykBin: "ryk",
			piAskRoot: askRoot,
		});
		const { ctx } = makeCtx({ hasUI: true, mode: "tui" });
		(ctx.ui as { select?: unknown }).select = async () => {
			throw new Error("child must not local-select on protocol failure");
		};

		const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
		assert.equal(result?.block, true);
		assert.match(result?.reason ?? "", /malformed|Fail-closed|unavailable/i);
		assert.equal(listPendingRequests(parentAskDir(askRoot, parentId)).length, 0);
	} finally {
		if (previous === undefined) delete process.env.PI_SUBAGENT_PARENT_SESSION;
		else process.env.PI_SUBAGENT_PARENT_SESSION = previous;
		if (previousRoot === undefined) delete process.env.RYK_PI_ASK_ROOT;
		else process.env.RYK_PI_ASK_ROOT = previousRoot;
		rmSync(askRoot, { recursive: true, force: true });
	}
});

test("child process failure follows unavailable policy", async () => {
	const { pi, handlers } = makePi();
	const { spawn } = makeSpawn([
		{ error: new Error("ENOENT") },
		{ error: new Error("ENOENT") },
	]);
	installRykExtension(pi, { spawn, rykBin: "missing-orca" });
	const { ctx } = makeCtx({ hasUI: false, mode: "print" });

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result.block, true);
	assert.match(result.reason, /ryk is unavailable|spawn_failed/i);
});

test("repeated protocol failures notify degraded once without allowing", async () => {
	const { pi, handlers } = makePi();
	const plans = Array.from({ length: PROTOCOL_DEGRADED_THRESHOLD * 2 }, () => ({
		code: 0 as number,
		stdout: "{not-json",
	}));
	const { spawn, calls } = makeSpawn(plans);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx, notifications } = makeCtx({ hasUI: false, mode: "print" });

	for (let i = 0; i < PROTOCOL_DEGRADED_THRESHOLD; i++) {
		const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
		assert.equal(result.block, true, `call ${i} must fail closed`);
	}
	// Two attempts per tool call (retry) × N failures.
	assert.equal(calls.length, PROTOCOL_DEGRADED_THRESHOLD * 2);
	const degraded = notifications.filter((n) =>
		/protocol degraded/i.test(n.message),
	);
	assert.equal(degraded.length, 1);
	assert.equal(degraded[0]?.type, "warning");
});

test("session bypass allows subsequent bash calls during same session", async () => {
	const { pi, handlers, commands } = makePi();
	const { spawn, calls } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();
	await commands.get("ryk-stop")!.handler("", ctx);

	const first = await fireToolCall(handlers.get("tool_call")![0], ctx);
	const second = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(first, undefined);
	assert.equal(second, undefined);
	assert.equal(calls.length, 0);
});

test("protocol failure on one session does not disable another", async () => {
	const { pi, handlers } = makePi();
	const err = { code: 3 as number, stdout: errorJson() };
	const { spawn, calls } = makeSpawn([
		err,
		{ code: 0, stdout: allowJson() },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const firstSession = makeCtx();
	const secondSession = makeCtx({
		sessionManager: { getSessionId: () => "session-b" },
	});

	const first = await fireToolCall(handlers.get("tool_call")![0], firstSession.ctx);
	const result = await fireToolCall(
		handlers.get("tool_call")![0],
		secondSession.ctx,
	);
	assert.equal(first?.block, true);
	assert.equal(result, undefined);
	assert.equal(calls.length, 2);
});

test("malformed bash tool calls fail closed", async () => {
	const { pi, handlers } = makePi();
	const { spawn, calls } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx();

	const result = await handlers.get("tool_call")![0](
		{ toolName: "bash", input: { command: 123 } },
		ctx,
	);
	assert.equal(result.block, true);
	assert.match(result.reason, /malformed Pi bash tool call/);
	assert.equal(calls.length, 0);
});

test("/ryk-doctor handles ryk present", async () => {
	const { pi, commands } = makePi();
	const { spawn } = makeSpawn([{ code: 0, stdout: '{"ok":true}' }]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx, notifications } = makeCtx();

	await commands.get("ryk-doctor")!.handler("", ctx);
	assert.equal(notifications.at(-1)?.type, "info");
	assert.match(notifications.at(-1)!.message, /ok/);
	assert.match(notifications.at(-1)!.message, /Coverage:/);
	assert.match(notifications.at(-1)!.message, /bash \+ write \+ edit \+ read policy-protected/);
});

test("/ryk-doctor handles ryk missing", async () => {
	const { pi, commands } = makePi();
	const { spawn } = makeSpawn([{ error: new Error("ENOENT") }]);
	installRykExtension(pi, { spawn, rykBin: "missing-orca" });
	const { ctx, notifications } = makeCtx();

	await commands.get("ryk-doctor")!.handler("", ctx);
	assert.equal(notifications.at(-1)?.type, "error");
	assert.match(notifications.at(-1)!.message, /not found/);
	assert.match(notifications.at(-1)!.message, /Coverage:/);
});

test("/ryk-stop disables Pi bash protection until /ryk-start re-enables it", async () => {
	const cwd = mkdtempSync(resolve(tmpdir(), "ryk-pi-"));
	mkdirSync(resolve(cwd, ".ryk"));
	writeFileSync(resolve(cwd, ".ryk/policy.yaml"), "version: 1\n");
	const { pi, commands, handlers } = makePi();
	const { spawn, calls } = makeSpawn([
		{ code: 0, stdout: "healthy" },
		{ code: 0, stdout: allowJson() },
	]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx, notifications, statuses } = makeCtx({ cwd });

	await commands.get("ryk-stop")!.handler("", ctx);
	const stopped = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"git status",
	);
	await commands.get("ryk-start")!.handler("", ctx);
	const restarted = await fireToolCall(
		handlers.get("tool_call")![0],
		ctx,
		"git status",
	);

	assert.equal(stopped, undefined);
	assert.equal(restarted, undefined);
	assert.deepEqual(
		calls.map((call) => call.args),
		[["doctor"], ["evaluate", "--json", "--stdin"]],
	);
	assert.equal(
		notifications.some((entry) =>
			entry.message.includes("disabled for this Pi session"),
		),
		true,
	);
	assert.equal(
		notifications.some((entry) => entry.message.includes("enabled")),
		true,
	);
	assert.equal(
		statuses.some((entry) => entry.text === "rykan v bypass"),
		true,
	);
	assert.equal(statuses.at(-1)?.text, "rykan v ready");
	rmSync(cwd, { recursive: true, force: true });
});

test("/ryk-start re-enables without invoking the CLI start command", async () => {
	const cwd = mkdtempSync(resolve(tmpdir(), "ryk-pi-"));
	mkdirSync(resolve(cwd, ".ryk"));
	writeFileSync(resolve(cwd, ".ryk/policy.yaml"), "version: 1\n");
	const present = makePi();
	const presentSpawn = makeSpawn([{ code: 0, stdout: "healthy" }]);
	installRykExtension(present.pi, {
		spawn: presentSpawn.spawn,
		rykBin: "ryk",
	});
	const presentCtx = makeCtx({ cwd });
	await present.commands.get("ryk-start")!.handler("", presentCtx.ctx);
	assert.deepEqual(
		presentSpawn.calls.map((call) => call.args),
		[["doctor"]],
	);
	assert.equal(presentCtx.notifications.at(-1)?.type, "info");

	const missing = makePi();
	const missingSpawn = makeSpawn([{ error: new Error("ENOENT") }]);
	installRykExtension(missing.pi, {
		spawn: missingSpawn.spawn,
		rykBin: "missing-orca",
	});
	const missingCtx = makeCtx();
	await missing.commands.get("ryk-start")!.handler("", missingCtx.ctx);
	assert.equal(missingCtx.notifications.at(-1)?.type, "error");
	assert.equal(
		missingSpawn.calls.some((call) => call.args.includes("start")),
		false,
	);
	rmSync(cwd, { recursive: true, force: true });
});

test("/ryk-mode changes mode", async () => {
	const { pi, commands } = makePi();
	installRykExtension(pi, { spawn: makeSpawn().spawn, rykBin: "ryk" });
	const { ctx, notifications } = makeCtx();

	await commands.get("ryk-mode")!.handler("strict", ctx);
	assert.match(notifications.at(-1)!.message, /strict/);
	assert.match(notifications.at(-1)!.message, /Coverage:/);
	assert.match(notifications.at(-1)!.message, /ryk run/);
	assert.match(notifications.at(-1)!.message, /prefer strict|Production/i);

	await commands.get("ryk-mode")!.handler("", ctx);
	assert.match(notifications.at(-1)!.message, /ryk Pi mode: strict/);
	assert.match(notifications.at(-1)!.message, /bash \+ write \+ edit \+ read policy-protected/);
});

test("no shell interpolation is used when invoking ryk", async () => {
	const { spawn, calls } = makeSpawn([{ code: 0, stdout: allowJson() }]);
	await runRykEvaluate(
		buildEvaluateRequest("echo safe", { cwd: process.cwd(), mode: "print" }),
		{
			spawn,
			rykBin: "ryk",
			timeoutMs: 1_000,
		},
	);

	assert.equal(calls[0].file, "ryk");
	assert.deepEqual(calls[0].args, ["evaluate", "--json", "--stdin"]);
	assert.equal(calls[0].options.shell, false);
	const request = JSON.parse(calls[0].stdin[0]) as RykEvaluateRequest;
	assert.equal(request.command, "echo safe");
	assert.equal(request.source.host, "pi");
});

test("runRykEvaluate maps decision ask exit 0 to kind ask", async () => {
	const { spawn } = makeSpawn([{ code: 0, stdout: askJson() }]);
	const decision = await runRykEvaluate(
		buildEvaluateRequest("git push --force", {
			cwd: process.cwd(),
			mode: "tui",
		}),
		{
			spawn,
			rykBin: "ryk",
			timeoutMs: 1_000,
		},
	);

	assert.equal(decision.kind, "ask");
	if (decision.kind === "ask") {
		assert.match(decision.reason, /requires approval/i);
		assert.equal(
			(decision.response as { decision?: string }).decision,
			"ask",
		);
	}
});

test("oversized ryk output follows unavailable policy", async () => {
	const { pi, handlers } = makePi();
	const huge = "x".repeat(1024 * 1024 + 1);
	const plan = { code: 0 as number, stdout: huge };
	const { spawn } = makeSpawn([plan, plan]);
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const { ctx } = makeCtx({ hasUI: false, mode: "print" });

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result.block, true);
	assert.match(result.reason, /maximum size|output_too_large/i);
});

test("helpers resolve modes and sanitize reasons", () => {
	assert.equal(resolveUnavailableMode("auto", { hasUI: true }), "ask");
	assert.equal(
		resolveUnavailableMode("auto", { hasUI: false }),
		"noninteractive-block",
	);
	assert.equal(
		resolveUnavailableMode("auto", { hasUI: true, mode: "print" }),
		"noninteractive-block",
	);
	assert.equal(
		resolveUnavailableMode("auto", { hasUI: true, mode: "json" }),
		"noninteractive-block",
	);
	assert.equal(
		resolveUnavailableMode("ask", { hasUI: true, mode: "print" }),
		"noninteractive-block",
	);
	assert.match(
		safeRykReason({ reason: "blocked token=abc123", rule_id: "rule" }),
		/Rykan V blocked this bash command: blocked token=\[redacted\] • rule rule/,
	);
});

test("buildEvaluateRequest resolves relative cwd", () => {
	const request = buildEvaluateRequest("git status", { cwd: ".", mode: "tui" });
	assert.equal(request.cwd, resolve("."));
});

test("buildEvaluateRequest includes the stable Pi session id", () => {
	const request = buildEvaluateRequest("git status", {
		cwd: process.cwd(),
		mode: "tui",
		sessionManager: { getSessionId: () => "pi-session-42" },
	});
	assert.equal(request.source.session_id, "pi-session-42");
});

test("ryk timeout follows unavailable policy", async () => {
	const { pi, handlers } = makePi();
	const spawn = (): FakeChild => {
		const child = new FakeChild();
		setTimeout(() => child.close(143), 5);
		return child;
	};
	installRykExtension(pi, { spawn, rykBin: "ryk", timeoutMs: 1 });
	const { ctx } = makeCtx({ hasUI: false, mode: "print" });

	const result = await fireToolCall(handlers.get("tool_call")![0], ctx);
	assert.equal(result.block, true);
	assert.match(result.reason, /timed out/);
});

test("makePi records registerMessageRenderer", () => {
	const { pi, renderers } = makePi();
	pi.registerMessageRenderer("probe-type", (_message, _options, theme) =>
		theme.fg("error", "x"),
	);
	assert.equal(renderers.has("probe-type"), true);
	const renderer = renderers.get("probe-type")!;
	const result = renderer(
		{ customType: "probe-type", content: "body", display: true },
		{ expanded: false, outputPad: 0 },
		makeThemeStub(),
	);
	assert.match(String(result), /\[error\]/);
});

test("installRykExtension registers decision message renderer", () => {
	const { pi, renderers } = makePi();
	const { spawn } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	assert.equal(renderers.size, 1);
	assert.equal(renderers.has("rykanv-decision"), true);
});

test("decision message renderer returns a TUI component with render()", () => {
	const { pi, renderers } = makePi();
	const { spawn } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const renderer = renderers.get("rykanv-decision");
	assert.ok(renderer);

	const result = renderer(
		{
			customType: "rykanv-decision",
			content: "BLOCKED .env",
			display: true,
			details: {
				variant: "block",
				title: DISPLAY_BRAND,
				summary: "blocked secret file",
			},
		},
		{ expanded: false, outputPad: 1 },
		makeThemeStub(),
	);

	assert.notEqual(typeof result, "string");
	assert.equal(typeof result, "object");
	assert.ok(result !== null);
	const component = result as { render?: (width: number) => unknown };
	assert.equal(typeof component.render, "function");
	const lines = component.render!(80);
	assert.ok(Array.isArray(lines));
	assert.ok(lines.every((line) => typeof line === "string"));
	assert.ok(lines.some((line) => line.includes("blocked secret file")));
	assert.ok(lines.some((line) => /Blocked/.test(line)));
	assert.ok(lines.some((line) => line.includes("[error]")));
});

test("decision message renderer ask variant uses warning tone and is renderable", () => {
	const { pi, renderers } = makePi();
	const { spawn } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const renderer = renderers.get("rykanv-decision")!;
	const result = renderer(
		{
			customType: "rykanv-decision",
			content: "ASK cat .env",
			display: true,
			details: {
				variant: "ask",
				title: DISPLAY_BRAND,
				summary: "needs approval",
			},
		},
		{ expanded: false, outputPad: 1 },
		makeThemeStub(),
	);
	const component = result as { render: (width: number) => string[] };
	const lines = component.render(40);
	assert.ok(lines.some((line) => line.includes("[warning]")));
	assert.ok(lines.some((line) => /Needs approval/.test(line)));
	assert.ok(lines.some((line) => line.includes("needs approval")));
});

test("decision message renderer wait variant and empty content stay renderable", () => {
	const { pi, renderers } = makePi();
	const { spawn } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const renderer = renderers.get("rykanv-decision")!;

	const waitResult = renderer(
		{
			customType: "rykanv-decision",
			content: "WAIT parent",
			display: true,
			details: {
				variant: "wait",
				title: DISPLAY_BRAND,
				summary: "waiting on parent",
			},
		},
		{ expanded: false, outputPad: 1 },
		makeThemeStub(),
	);
	const waitLines = (waitResult as { render: (width: number) => string[] }).render(80);
	assert.ok(waitLines.some((line) => line.includes("[dim]")));
	assert.ok(waitLines.some((line) => /Waiting/.test(line)));
	assert.ok(waitLines.some((line) => line.includes("waiting on parent")));

	const emptyResult = renderer(
		{
			customType: "rykanv-decision",
			content: "",
			display: true,
			details: {
				variant: "block",
				title: DISPLAY_BRAND,
				summary: "blocked secret file",
			},
		},
		{ expanded: false, outputPad: 1 },
		makeThemeStub(),
	);
	assert.notEqual(typeof emptyResult, "string");
	const emptyLines = (emptyResult as { render: (width: number) => string[] }).render(80);
	assert.ok(Array.isArray(emptyLines));
	assert.ok(emptyLines.every((line) => typeof line === "string"));
	assert.ok(emptyLines.some((line) => line.includes(DISPLAY_BRAND)));
});

test("decision message renderer never returns a string", () => {
	const { pi, renderers } = makePi();
	const { spawn } = makeSpawn();
	installRykExtension(pi, { spawn, rykBin: "ryk" });
	const renderer = renderers.get("rykanv-decision")!;

	for (const message of [
		{ content: "plain string body", details: undefined },
		{
			content: "",
			details: {
				variant: "block" as const,
				title: DISPLAY_BRAND,
				summary: "blocked",
			},
		},
	]) {
		const result = renderer(
			{ customType: "rykanv-decision", display: true, ...message },
			{ expanded: false, outputPad: 1 },
			makeThemeStub(),
		);
		assert.notEqual(typeof result, "string");
		assert.equal(typeof (result as { render?: unknown }).render, "function");
		const lines = (result as { render: (width: number) => string[] }).render(80);
		assert.ok(Array.isArray(lines));
		assert.ok(lines.every((line) => typeof line === "string"));
	}
});

test("buildRykWidget deny/ask/wait cards stay borderless with Why/Cmd/Meta/Next", () => {
	const deny = buildRykWidget({
		variant: "block",
		title: DISPLAY_BRAND,
		summary: "destructive filesystem command",
		preview: "rm -rf /",
		rule: "core.filesystem:destructive-rm",
		nextStep: "Use a project-scoped path",
	});
	const denyText = deny.join("\n");
	assert.match(denyText, /RYKAN V · Blocked/);
	assert.match(denyText, /Why\s+destructive filesystem command/);
	assert.match(denyText, /Cmd\s+rm -rf \//);
	assert.match(denyText, /Meta\s+core\.filesystem:destructive-rm/);
	assert.match(denyText, /Next\s+Use a project-scoped path/);
	assert.ok(!/[┏┓┗┛┃━┌┐└┘│─]/.test(denyText));

	const ask = buildRykWidget({
		variant: "ask",
		title: DISPLAY_BRAND,
		summary: "needs approval for write",
	});
	const askText = ask.join("\n");
	assert.match(askText, /RYKAN V · Needs approval/);
	assert.match(askText, /Why\s+needs approval for write/);
	assert.match(askText, /Tip\s+Use the prompt below/);
	assert.ok(!/[┏┓┗┛┃━┌┐└┘│─]/.test(askText));

	const wait = buildRykWidget({
		variant: "wait",
		title: DISPLAY_BRAND,
		summary: "Waiting for approval in the parent Pi session (bash).",
		preview: "rm -rf /",
		nextStep:
			"Switch to the main Pi window and answer the prompt. This card is not interactive.",
		timeoutHint: "Auto-denies in ~30s if unanswered.",
		rule: "rykanv:parent-ask-wait",
	});
	const waitText = wait.join("\n");
	assert.match(waitText, /RYKAN V · Waiting/);
	assert.match(waitText, /Why\s+Waiting for approval/);
	assert.match(waitText, /Cmd\s+rm -rf \//);
	assert.match(waitText, /Meta\s+rykanv:parent-ask-wait/);
	assert.match(waitText, /Next\s+Switch to the main Pi window/);
	assert.match(waitText, /Wait\s+Auto-denies in ~30s/);
	assert.ok(!/[┏┓┗┛┃━┌┐└┘│─]/.test(waitText));
});

test("buildThemedDecisionLines uses theme tokens and matches plaintext rows", () => {
	const card = {
		variant: "block" as const,
		title: DISPLAY_BRAND,
		summary: "blocked secret file",
		preview: "cat .env",
		rule: "files.read.deny[0]",
	};
	const themed = buildThemedDecisionLines(card, makeThemeStub());
	const plain = buildRykWidget(card);
	assert.ok(themed.some((line) => line.includes("[error]")));
	assert.ok(themed.some((line) => line.includes("[dim]")));
	assert.ok(themed.some((line) => /Blocked/.test(line)));
	assert.ok(themed.some((line) => line.includes("cat .env")));
	assert.equal(themed.length, plain.length);
	assert.ok(!themed.some((line) => /[┏┓┗┛┃━┌┐└┘│─]/.test(line)));
});

function makeEpermFs(): ParentAskFs {
	const err = Object.assign(new Error("EPERM: operation not permitted, mkdir"), {
		code: "EPERM",
		errno: -1,
		syscall: "mkdir",
	});
	const deny = (): never => {
		throw err;
	};
	return {
		existsSync: deny,
		mkdirSync: deny,
		writeFileSync: deny,
		readFileSync: deny,
		readdirSync: deny,
		renameSync: deny,
		rmSync: deny,
	};
}

test("parent-ask mkdir EPERM does not throw from resolvePiAskRoot or parentAskDir", () => {
	const fsApi = makeEpermFs();
	const root = resolvePiAskRoot(
		{
			HOME: "/Users/nobody",
			TMPDIR: "/tmp/ryk-session-tmp",
			RYK_PI_ASK_ROOT: "",
		},
		fsApi,
	);
	assert.equal(root, "/Users/nobody/.local/state/ryk/pi-ask");
	assert.doesNotThrow(() =>
		parentAskDir("/Users/nobody/.local/state/ryk/pi-ask", "session-a", fsApi),
	);
	assert.doesNotThrow(() =>
		addSessionGrant("/Users/nobody/.local/state/ryk/pi-ask/session-a", "bash", 1, fsApi),
	);
	assert.equal(
		hasSessionGrant("/Users/nobody/.local/state/ryk/pi-ask/session-a", "bash", fsApi),
		false,
	);
});

test("session_start survives parent-ask mkdir EPERM", async () => {
	const { pi, handlers } = makePi();
	const { spawn } = makeSpawn([{ code: 0, stdout: "healthy" }]);
	installRykExtension(pi, {
		spawn,
		rykBin: "ryk",
		piAskFs: makeEpermFs(),
		piAskRoot: "/Users/nobody/.local/state/ryk/pi-ask",
		parentAskPollMs: 0,
	});
	const { ctx } = makeCtx({
		sessionManager: {
			getSessionId: () => "01a001e5-fa69-7b13-bcf0-c77f24c77f82",
		},
	});
	const rejections: unknown[] = [];
	const onReject = (reason: unknown) => {
		rejections.push(reason);
	};
	process.on("unhandledRejection", onReject);
	try {
		assert.doesNotThrow(() => handlers.get("session_start")![0]({}, ctx));
		await flushAsyncWork();
	} finally {
		process.off("unhandledRejection", onReject);
	}
	assert.equal(rejections.length, 0, String(rejections[0]));
});

test("tool_call survives parent-ask mkdir EPERM", async () => {
	const { pi, handlers } = makePi();
	const { spawn } = makeSpawn([
		{
			code: 0,
			stdout: JSON.stringify({
				version: 1,
				decision: "allow",
				risk: "low",
				category: "shell",
				reason: "ok",
			}),
		},
	]);
	installRykExtension(pi, {
		spawn,
		rykBin: "ryk",
		piAskFs: makeEpermFs(),
		piAskRoot: "/Users/nobody/.local/state/ryk/pi-ask",
		parentAskPollMs: 0,
	});
	const { ctx } = makeCtx({
		sessionManager: {
			getSessionId: () => "01a001e5-fa69-7b13-bcf0-c77f24c77f82",
		},
	});
	await handlers.get("session_start")![0]({}, ctx);
	await flushAsyncWork();
	await assert.doesNotReject(() =>
		fireToolCall(handlers.get("tool_call")![0], ctx, "git status"),
	);
});

test("subagent residual ask permits when parent-ask FS is EPERM", async () => {
	await withClearedUnattendedEnv(async () => {
	const previous = process.env.PI_SUBAGENT_PARENT_SESSION;
	process.env.PI_SUBAGENT_PARENT_SESSION = "parent-eperm";
	try {
		const { pi, handlers } = makePi();
		const { spawn } = makeSpawn([
			{ code: 7, stdout: decideJson("ask", "file.write") },
		]);
		installRykExtension(pi, {
			spawn,
			rykBin: "ryk",
			piAskFs: makeEpermFs(),
			piAskRoot: "/Users/nobody/.local/state/ryk/pi-ask",
			parentAskPollMs: 0,
		});
		const { ctx } = makeCtx({
			hasUI: true,
			mode: "tui",
			sessionManager: {
				getSessionId: () => "child-eperm",
			},
		});
		(ctx.ui as { select?: () => Promise<string> }).select = async () => {
			throw new Error("child must not call select");
		};
		const result = await fireToolCall(
			handlers.get("tool_call")![0],
			ctx,
			"",
			"write",
			{ path: "src/main.ts", content: "x" },
		);
		assert.equal(result, undefined);
	} finally {
		if (previous === undefined) delete process.env.PI_SUBAGENT_PARENT_SESSION;
		else process.env.PI_SUBAGENT_PARENT_SESSION = previous;
	}
	});
});
