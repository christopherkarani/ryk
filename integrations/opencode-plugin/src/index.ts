import { execFileSync } from 'child_process';
import { existsSync, realpathSync, statSync } from 'fs';
import { delimiter, isAbsolute, join, resolve } from 'path';

interface RykResponse {
  version?: number;
  decision: 'allow' | 'block' | 'warn' | 'ask' | 'context_only' | 'error';
  risk?: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  category?: string;
  reason?: string;
  rule?: string | null;
  message?: string;
  redactions?: Array<{ field: string; reason: string }>;
  host_limitations?: string[];
  remediation_commands?: string[];
  suggestions?: string[];
}

/** Minimal OpenCode plugin context (auto-load + typed Plugin). */
type PluginContext = {
  directory: string;
  worktree: string;
  client?: {
    tui?: {
      showToast?: (input: {
        body: {
          title?: string;
          message: string;
          variant?: 'info' | 'success' | 'warning' | 'error';
          duration?: number;
        };
      }) => Promise<unknown>;
    };
  };
};

type ToolExecuteBeforeInput = {
  tool: string;
  sessionID: string;
  callID: string;
};

type ToolExecuteBeforeOutput = {
  args: Record<string, unknown>;
};

type ToolExecuteAfterInput = ToolExecuteBeforeInput & {
  args: Record<string, unknown>;
};

type ToolExecuteAfterOutput = {
  title: string;
  output: string;
  metadata: unknown;
};

type PermissionAskOutput = {
  status: 'ask' | 'deny' | 'allow';
};

type ShellEnvInput = {
  cwd: string;
  sessionID?: string;
  callID?: string;
};

type ShellEnvOutput = {
  env: Record<string, string>;
};

type CommandExecuteBeforeInput = {
  command: string;
  sessionID: string;
  arguments: string;
};

type CommandExecuteBeforeOutput = {
  parts: unknown[];
};

type PluginHooks = {
  event?: (input: { event: Record<string, unknown> }) => Promise<void>;
  'tool.execute.before'?: (
    input: ToolExecuteBeforeInput,
    output: ToolExecuteBeforeOutput
  ) => Promise<void>;
  'tool.execute.after'?: (
    input: ToolExecuteAfterInput,
    output: ToolExecuteAfterOutput
  ) => Promise<void>;
  'permission.ask'?: (input: Record<string, unknown>, output: PermissionAskOutput) => Promise<void>;
  'shell.env'?: (input: ShellEnvInput, output: ShellEnvOutput) => Promise<void>;
  'command.execute.before'?: (
    input: CommandExecuteBeforeInput,
    output: CommandExecuteBeforeOutput
  ) => Promise<void>;
};

/** Decisions that may pass through on a blocking path (ask kept for permission.ask UX). */
const ALLOW_DECISIONS = new Set(['allow', 'warn', 'context_only', 'ask']);

/** Decisions that do not veto tool.execute.before after parsing. */
const BLOCKING_PASS_THROUGH = new Set(['allow', 'warn', 'context_only']);

const SECRET_KEYS = [
  'password', 'token', 'secret', 'api_key', 'apikey', 'api_secret',
  'auth', 'authorization', 'bearer', 'private_key', 'access_token',
  'refresh_token', 'credential', 'passwd', 'pwd',
];

/** Env var name patterns scrubbed from shell.env output (defense in depth). */
const SECRET_ENV_NAME_RE =
  /^(.*(_)?(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_KEY|REFRESH|CREDENTIAL|AUTH).*|AWS_.*|AZURE_.*|GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|NPM_TOKEN|PYPI_TOKEN|SSH_AUTH_SOCK)$/i;

const AUDIT_EVENT_TYPES = new Set([
  'session.created',
  'permission.replied',
  'permission.asked',
  'file.edited',
  'command.executed',
  'session.updated',
  'session.idle',
  'session.error',
]);

/** Paths that must never be read via OpenCode tools (docs .env protection pattern). */
const BLOCKED_READ_BASENAMES = new Set([
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.staging',
  '.env.test',
]);

function redactSecrets(data: unknown): unknown {
  if (data === null || data === undefined) return data;
  if (typeof data === 'string') return data;
  if (Array.isArray(data)) return data.map(redactSecrets);
  if (typeof data !== 'object') return data;

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    const lowerKey = key.toLowerCase();
    if (SECRET_KEYS.some((s) => lowerKey.includes(s))) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = redactSecrets(value);
    }
  }
  return result;
}

function scrubEnv(env: Record<string, string>): { env: Record<string, string>; removed: string[] } {
  const next: Record<string, string> = {};
  const removed: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    if (SECRET_ENV_NAME_RE.test(key)) {
      removed.push(key);
      continue;
    }
    next[key] = value;
  }
  return { env: next, removed };
}

function buildPayload(event: string, data: unknown, sessionId?: string): object {
  return {
    version: 1,
    host: 'opencode',
    event,
    payload: redactSecrets(data),
    session_id: sessionId,
    timestamp: new Date().toISOString(),
  };
}

function failClosedBlock(reason: string, message: string): RykResponse {
  return {
    decision: 'block',
    risk: 'high',
    category: 'unknown',
    reason,
    message,
  };
}

function softAllow(reason: string, message?: string): RykResponse {
  return {
    decision: 'allow',
    risk: 'unknown',
    category: 'unknown',
    reason,
    message,
  };
}

function normalizeBlockingDecision(
  decision: string,
  base: Partial<RykResponse>
): RykResponse {
  if (decision === 'block' || decision === 'error') {
    return {
      ...base,
      decision: 'block',
      risk: base.risk ?? 'high',
      category: base.category ?? 'unknown',
      reason: base.reason,
      message:
        base.message ||
        base.reason ||
        (decision === 'error'
          ? 'ryk returned error; blocking as a precaution.'
          : 'ryk blocked this command.'),
    };
  }
  if (!ALLOW_DECISIONS.has(decision)) {
    return failClosedBlock(
      'ryk_unrecognized_decision',
      `ryk returned unrecognized decision "${decision}"; blocking as a precaution.`
    );
  }
  return {
    decision: decision as RykResponse['decision'],
    risk: base.risk,
    category: base.category,
    reason: base.reason,
    message: base.message,
    version: base.version,
    rule: base.rule,
    redactions: base.redactions,
    host_limitations: base.host_limitations,
    remediation_commands: base.remediation_commands,
    suggestions: base.suggestions,
  };
}

function parseOptionalStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out = value.filter((item): item is string => typeof item === 'string');
  return out.length > 0 ? out : undefined;
}

/**
 * Parse ryk hook stdout into a decision.
 * Non-blocking: soft-allow on empty/malformed.
 * Blocking: fail closed on empty/whitespace, parse errors, missing/non-string decision,
 * `error`, and unrecognized decisions. `ask` is preserved for OpenCode permission.ask UX;
 * tool.execute.before still hard-blocks ask via applyBlockingDecision.
 */
export function parseHookResponse(stdout: string, blocking: boolean): RykResponse {
  const fail = (reason: string, blockMsg: string, softMsg: string): RykResponse =>
    blocking ? failClosedBlock(reason, blockMsg) : softAllow(reason, softMsg);

  if (!stdout.trim()) {
    return fail(
      'ryk_empty_response',
      'ryk returned empty output; blocking as a precaution.',
      'ryk returned empty output; allowing non-blocking event.'
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return fail(
      'ryk_parse_error',
      'ryk returned unreadable JSON; blocking as a precaution.',
      'ryk returned unreadable JSON; allowing non-blocking event.'
    );
  }

  if (!parsed || typeof parsed !== 'object') {
    return fail(
      'ryk_missing_decision',
      'ryk response missing decision; blocking as a precaution.',
      'ryk response missing decision; allowing non-blocking event.'
    );
  }

  const record = parsed as Record<string, unknown>;
  const decisionRaw = record.decision;
  if (typeof decisionRaw !== 'string') {
    return fail(
      'ryk_missing_decision',
      'ryk response missing decision; blocking as a precaution.',
      'ryk response missing decision; allowing non-blocking event.'
    );
  }

  const base: Partial<RykResponse> = {
    version: typeof record.version === 'number' ? record.version : undefined,
    risk: record.risk as RykResponse['risk'],
    category: typeof record.category === 'string' ? record.category : undefined,
    reason: typeof record.reason === 'string' ? record.reason : undefined,
    message: typeof record.message === 'string' ? record.message : undefined,
    rule: (record.rule as string | null | undefined) ?? undefined,
    remediation_commands: parseOptionalStringArray(record.remediation_commands),
    suggestions: parseOptionalStringArray(record.suggestions),
  };

  if (!blocking) {
    return {
      decision: decisionRaw as RykResponse['decision'],
      ...base,
    };
  }

  return normalizeBlockingDecision(decisionRaw, base);
}

/**
 * Resolve and attest the ryk binary. A path is not an authority: candidates
 * must answer `ryk version --json` with product `ryk` and a semver version.
 * Workspace candidates remain opt-in for development only. PATH lookup is
 * implemented directly so Windows does not depend on the Unix-only `which`.
 */
export function findRyk(cwd?: string, platform: NodeJS.Platform = process.platform): string | null {
  const envBin = process.env.RYK_BIN?.trim();
  if (envBin) {
    if (envBin.includes('/') || envBin.includes('\\')) {
      if (!isAbsolute(envBin)) return null;
      return attestRykCandidate(envBin, cwd) ? canonicalPath(envBin) : null;
    }
    const bin = resolveOnPath(envBin, platform);
    return bin && attestRykCandidate(bin, cwd) ? canonicalPath(bin) : null;
  }

  const pathBin = resolveOnPath('ryk', platform);
  if (pathBin && attestRykCandidate(pathBin, cwd)) return canonicalPath(pathBin);

  // Dev-only: never trust agent-writable workspace bins in production loads.
  if (process.env.RYK_ALLOW_WORKSPACE_BIN === '1') {
    const candidates: string[] = [];
    if (cwd) {
      candidates.push(join(cwd, 'zig-out', 'bin', 'ryk'));
      candidates.push(join(cwd, '..', 'zig-out', 'bin', 'ryk'));
      candidates.push(join(cwd, '..', '..', 'zig-out', 'bin', 'ryk'));
    }
    candidates.push(resolve('zig-out', 'bin', 'ryk'));
    candidates.push(resolve('..', 'zig-out', 'bin', 'ryk'));
    candidates.push(resolve('..', '..', 'zig-out', 'bin', 'ryk'));

    for (const p of candidates) {
      if (attestRykCandidate(p, cwd)) return canonicalPath(p);
    }
  }

  return null;
}

const RYK_VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function canonicalPath(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

function isWorkspaceCandidate(path: string, cwd?: string): boolean {
  if (process.env.RYK_ALLOW_WORKSPACE_BIN === '1') return false;
  const canonical = canonicalPath(path).replaceAll('\\', '/');
  if (canonical.includes('/node_modules/.bin/')) return true;
  if (!cwd) return false;
  const workspace = canonicalPath(cwd).replaceAll('\\', '/').replace(/\/$/, '');
  return canonical === workspace || canonical.startsWith(`${workspace}/`);
}

function attestRykCandidate(path: string, cwd?: string): boolean {
  if (!existsSync(path) || isWorkspaceCandidate(path, cwd)) return false;
  try {
    if (!statSync(path).isFile()) return false;
    const output = execFileSync(path, ['version', '--json'], {
      encoding: 'utf-8',
      timeout: 3000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    const identity = JSON.parse(output) as { product?: unknown; version?: unknown };
    return identity.product === 'ryk' &&
      typeof identity.version === 'string' &&
      RYK_VERSION_RE.test(identity.version);
  } catch {
    return false;
  }
}

function resolveOnPath(name: string, platform: NodeJS.Platform): string | null {
  const names = platform === 'win32' && !name.toLowerCase().endsWith('.exe')
    ? [name, `${name}.exe`]
    : [name];
  for (const entry of (process.env.PATH ?? '').split(delimiter)) {
    if (!entry) continue;
    for (const candidateName of names) {
      const candidate = resolve(entry, candidateName);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

function callRyk(
  rykBin: string,
  event: string,
  data: unknown,
  sessionId: string | undefined,
  blocking: boolean
): RykResponse {
  const payloadJson = JSON.stringify(buildPayload(event, data, sessionId));

  try {
    // argv array — no shell interpolation of rykBin or event
    const stdout = execFileSync(rykBin, ['hook', 'opencode', event], {
      input: payloadJson,
      encoding: 'utf-8',
      timeout: blocking ? 15000 : 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: 1024 * 1024,
    });

    return parseHookResponse(stdout, blocking);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[ryk] Hook ${event} failed: ${message}`);

    return blocking
      ? failClosedBlock(
          'ryk_hook_error',
          'ryk hook failed; blocking as a precaution.'
        )
      : softAllow(
          'ryk_hook_error',
          'ryk hook failed; allowing because this event is non-blocking.'
        );
  }
}

function buildToolBeforePayload(
  input: ToolExecuteBeforeInput,
  output: ToolExecuteBeforeOutput
): Record<string, unknown> {
  return {
    tool: input.tool,
    sessionID: input.sessionID,
    callID: input.callID,
    ...output.args,
    args: output.args,
  };
}

/** First non-empty line of text (strips multi-line Recourse/Next walls). */
function firstLine(text: string): string {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed) return trimmed;
  }
  return '';
}

/**
 * Short one-line tool/toast copy for hard blocks.
 * Prefer rule → reason → first line of message. Never embed Recourse/Next walls.
 */
function formatShortBlock(response: RykResponse, context: string): string {
  let detail = '';
  if (typeof response.rule === 'string' && response.rule.trim()) {
    detail = firstLine(response.rule);
  } else if (typeof response.reason === 'string' && response.reason.trim()) {
    detail = firstLine(response.reason);
  } else if (typeof response.message === 'string' && response.message.trim()) {
    detail = firstLine(response.message);
  }
  if (!detail) {
    detail = 'blocked by policy';
  }
  // Belt-and-suspenders: strip same-line Recourse/Next if CLI ever packs them.
  detail = detail.replace(/\s*Recourse:\s*.*$/i, '').replace(/\s*Next:\s*.*$/i, '').trim() || detail;
  // Prefer ~120-char tool lines; keep room for the "ryk blocked …: " prefix.
  const maxDetail = 90;
  if (detail.length > maxDetail) {
    detail = `${detail.slice(0, maxDetail - 3)}...`;
  }
  return `ryk blocked ${context}: ${detail}`;
}

/**
 * Full operator detail for stderr only (not Error.message / chat tool card).
 */
function formatOperatorDetail(response: RykResponse, context: string): string {
  const base = response.message || response.reason || 'ryk blocked this command.';
  const parts = [`ryk blocked ${context}: ${base}`];
  if (response.remediation_commands && response.remediation_commands.length > 0) {
    parts.push(`Next: ${response.remediation_commands.slice(0, 3).join(' · ')}`);
  } else if (response.decision === 'ask') {
    parts.push(
      'This needs your approval. In a terminal: ryk allow-once <code>  (or ryk explain "<command>")'
    );
  }
  return parts.join('\n');
}

/** Cap toast RPC wait so a stuck TUI client cannot freeze the hard-block path. */
const TOAST_TIMEOUT_MS = 1500;

async function maybeToast(
  ctx: PluginContext,
  variant: 'info' | 'success' | 'warning' | 'error',
  title: string,
  message: string
): Promise<void> {
  const showToast = ctx.client?.tui?.showToast;
  if (!showToast) return;
  try {
    await Promise.race([
      showToast({
        body: {
          title,
          message: message.slice(0, 280),
          variant,
          duration: variant === 'error' ? 8000 : 5000,
        },
      }),
      new Promise<void>((resolve) => {
        setTimeout(resolve, TOAST_TIMEOUT_MS);
      }),
    ]);
  } catch {
    // Host toast is best-effort; never fail open on UI (block path still throws).
  }
}

/** Best-effort error toast then throw a short single-line Error. */
async function hardBlockWithToast(
  ctx: PluginContext,
  shortMsg: string,
  operatorDetail?: string
): Promise<never> {
  console.error(`[ryk] ${operatorDetail ?? shortMsg}`);
  await maybeToast(ctx, 'error', 'ryk blocked', shortMsg);
  throw new Error(shortMsg);
}

/**
 * Apply a blocking-path decision: warn/pass-through return; hard blocks toast
 * then throw a short Error. Full operator detail goes to stderr only.
 */
async function applyBlockingDecision(
  response: RykResponse,
  context: string,
  ctx: PluginContext
): Promise<void> {
  if (response.decision === 'warn') {
    console.warn(`[ryk] Warning: ${response.message || response.reason}`);
    return;
  }

  if (BLOCKING_PASS_THROUGH.has(response.decision)) {
    return;
  }

  // block, ask, error, unrecognized → veto tool execution
  await hardBlockWithToast(
    ctx,
    formatShortBlock(response, context),
    formatOperatorDetail(response, context)
  );
}

/** ryk decision → OpenCode permission.ask status. Unknown decisions fail closed to deny. */
const PERMISSION_STATUS: Record<string, PermissionAskOutput['status']> = {
  block: 'deny',
  error: 'deny',
  ask: 'ask',
  allow: 'allow',
  context_only: 'allow',
  // Keep host permission UI for advisory outcomes (do not auto-allow).
  warn: 'ask',
};

function applyPermissionDecision(response: RykResponse, output: PermissionAskOutput): void {
  const status = PERMISSION_STATUS[response.decision];
  if (!status) {
    const msg = response.message || response.reason || 'ryk returned an invalid permission decision';
    console.error(`[ryk] Blocked permission (fail-closed): ${msg}`);
    output.status = 'deny';
    return;
  }
  if (status === 'deny') {
    const msg = response.message || response.reason || 'ryk blocked this command.';
    console.error(`[ryk] Blocked permission: ${msg}`);
  }
  if (response.decision === 'warn') {
    console.warn(`[ryk] Permission warning: ${response.message || response.reason}`);
  }
  output.status = status;
}

function auditEventPayload(event: Record<string, unknown>): unknown {
  if (event.type === 'session.error') {
    return redactSecrets({
      message: event.message,
      stack: event.stack,
      type: event.type,
    });
  }
  return redactSecrets(event);
}

function sessionIdFromEvent(event: Record<string, unknown>): string | undefined {
  if (typeof event.sessionID === 'string') return event.sessionID;
  if (typeof event.session_id === 'string') return event.session_id;
  return undefined;
}

function sessionIdFromRecord(value: Record<string, unknown>): string | undefined {
  if (typeof value.sessionID === 'string') return value.sessionID;
  if (typeof value.session_id === 'string') return value.session_id;
  return undefined;
}

function pathFromArgs(args: Record<string, unknown>): string | undefined {
  for (const key of ['path', 'filePath', 'file_path', 'target_file', 'file', 'filename']) {
    const value = args[key];
    if (typeof value === 'string' && value.trim()) return value;
  }
  return undefined;
}

function isBlockedDotenvPath(pathValue: string): boolean {
  const normalized = pathValue.replace(/\\/g, '/');
  const base = normalized.split('/').pop() ?? normalized;
  if (BLOCKED_READ_BASENAMES.has(base)) return true;
  // .env.* variants (except example/sample templates)
  if (/^\.env(\.|$)/.test(base) && !/\.(example|sample|template)$/i.test(base)) return true;
  return false;
}

const READ_LIKE_TOOLS = new Set([
  'read',
  'read_file',
  'file_read',
  'cat',
]);

async function localDotenvGuard(
  tool: string,
  args: Record<string, unknown>,
  ctx: PluginContext
): Promise<void> {
  if (!READ_LIKE_TOOLS.has(tool.toLowerCase())) return;
  const pathValue = pathFromArgs(args);
  if (!pathValue) return;
  if (!isBlockedDotenvPath(pathValue)) return;
  // Keep path on one line (no embedded newlines from untrusted args).
  const safePath = firstLine(pathValue) || pathValue.replace(/\s+/g, ' ').slice(0, 80);
  const msg = `ryk blocked tool execution: reading ${safePath} is blocked (.env protection).`;
  await hardBlockWithToast(ctx, msg);
}

const MISSING_BINARY_MSG = 'ryk binary not found; blocking as a precaution.';

export default async function rykPlugin(ctx: PluginContext): Promise<PluginHooks> {
  const cwd = ctx.worktree || ctx.directory || process.cwd();
  // Fail closed on unexpected resolve errors so hooks still register.
  let rykBin: string | null = null;
  try {
    rykBin = findRyk(cwd);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[ryk] Binary resolve failed (fail-closed): ${message}`);
    rykBin = null;
  }

  if (!rykBin) {
    console.warn(
      '[ryk] Binary not found in PATH or typical build paths. ' +
        'Registering fail-closed veto hooks. ' +
        'Install ryk, then run: ryk plugin install opencode --yes.'
    );
    return {
      'tool.execute.before': async () => {
        await hardBlockWithToast(
          ctx,
          `ryk blocked tool execution: ${MISSING_BINARY_MSG}`,
          `Blocked tool execution: ${MISSING_BINARY_MSG}`
        );
      },
      'command.execute.before': async () => {
        await hardBlockWithToast(
          ctx,
          `ryk blocked command: ${MISSING_BINARY_MSG}`,
          `Blocked command: ${MISSING_BINARY_MSG}`
        );
      },
      'permission.ask': async (_input, output) => {
        console.error(`[ryk] Blocked permission: ${MISSING_BINARY_MSG}`);
        output.status = 'deny';
      },
      'shell.env': async (_input, output) => {
        const scrubbed = scrubEnv(output.env);
        output.env = scrubbed.env;
      },
    };
  }

  console.log(`[ryk] Plugin loaded. Binary: ${rykBin}`);

  return {
    event: async ({ event }) => {
      const eventType = typeof event.type === 'string' ? event.type : '';
      if (!AUDIT_EVENT_TYPES.has(eventType)) return;

      if (eventType === 'session.created') {
        console.log('[ryk] Plugin ready for session.');
      }

      await callRyk(
        rykBin,
        eventType,
        auditEventPayload(event),
        sessionIdFromEvent(event),
        false
      );
    },

    'tool.execute.before': async (input, output) => {
      // Local defense-in-depth (.env protection) before ryk round-trip.
      await localDotenvGuard(input.tool, output.args ?? {}, ctx);

      const response = callRyk(
        rykBin,
        'tool.execute.before',
        buildToolBeforePayload(input, output),
        input.sessionID,
        true
      );
      if (response.decision === 'warn') {
        await maybeToast(
          ctx,
          'warning',
          'ryk',
          response.message || response.reason || 'policy warning'
        );
      }
      await applyBlockingDecision(response, 'tool execution', ctx);
    },

    'tool.execute.after': async (input, output) => {
      await callRyk(
        rykBin,
        'tool.execute.after',
        {
          tool: input.tool,
          sessionID: input.sessionID,
          callID: input.callID,
          args: input.args,
          title: output.title,
          output: output.output,
          metadata: output.metadata,
        },
        input.sessionID,
        false
      );
    },

    'permission.ask': async (input, output) => {
      const sessionId = sessionIdFromRecord(input);
      const response = callRyk(rykBin, 'permission.asked', input, sessionId, true);
      // Host already presents permission UI: map via table (ask stays ask for resume).
      applyPermissionDecision(response, output);
      if (response.decision === 'warn' || response.decision === 'ask') {
        await maybeToast(
          ctx,
          'warning',
          'ryk approval',
          response.message || response.reason || 'needs your approval'
        );
      }
    },

    'command.execute.before': async (input, _output) => {
      // Slash/custom commands are not shell — send as tool name so ryk uses tool policy.
      const response = callRyk(
        rykBin,
        'command.execute.before',
        {
          tool: input.command,
          command_name: input.command,
          sessionID: input.sessionID,
          arguments: input.arguments,
        },
        input.sessionID,
        true
      );
      if (response.decision === 'warn') {
        await maybeToast(
          ctx,
          'warning',
          'ryk',
          response.message || response.reason || 'policy warning'
        );
      }
      await applyBlockingDecision(response, 'command', ctx);
    },

    'shell.env': async (input, output) => {
      // Scrub secrets from the env OpenCode will pass to shell tools.
      const beforeKeys = Object.keys(output.env);
      const scrubbed = scrubEnv(output.env);
      output.env = scrubbed.env;
      if (scrubbed.removed.length > 0) {
        console.warn(
          `[ryk] Scrubbed ${scrubbed.removed.length} secret env var(s) from shell.env`
        );
      }

      await callRyk(
        rykBin,
        'shell.env',
        {
          cwd: input.cwd,
          sessionID: input.sessionID,
          callID: input.callID,
          env: redactSecrets(output.env),
          scrubbed_keys: scrubbed.removed,
          env_key_count_before: beforeKeys.length,
          env_key_count_after: Object.keys(output.env).length,
        },
        input.sessionID,
        false
      );
    },
  };
}
