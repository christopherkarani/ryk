import { execFileSync, spawn } from 'child_process';
import { createHash } from 'crypto';
import { existsSync, lstatSync, realpathSync, readFileSync, statSync } from 'fs';
import { homedir, tmpdir } from 'os';
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
  /** Internal provenance bit; true only for a parsed Ryk `block` decision. */
  verifiedPolicyBlock?: boolean;
}

interface OpenClawBlockResult {
  block?: boolean;
  blockReason?: string;
}

interface OpenClawAgentToolResult {
  content: Array<{ type: 'text'; text: string }>;
  details: Record<string, unknown>;
}

interface OpenClawAgentTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  execute: (id: string, params: Record<string, unknown>) => Promise<OpenClawAgentToolResult>;
}

type OpenClawRegistrationMode =
  | 'full'
  | 'discovery'
  | 'tool-discovery'
  | 'setup-only'
  | 'setup-runtime'
  | 'cli-metadata';

interface PluginLogger {
  debug?: (message: string) => void;
  info: (message: string) => void;
  warn: (message: string) => void;
  error: (message: string) => void;
}

/**
 * Minimal type for the OpenClaw Plugin API passed at runtime.
 * Matches OpenClawPluginApi from the openclaw/plugin-sdk types.
 */
interface OpenClawPluginApi {
  id: string;
  name: string;
  version?: string;
  description?: string;
  source: string;
  rootDir?: string;
  registrationMode?: OpenClawRegistrationMode;
  config: unknown;
  pluginConfig?: Record<string, unknown>;
  runtime: unknown;
  logger: PluginLogger;
  registerTool?: (tool: OpenClawAgentTool, opts?: { optional?: boolean }) => void;
  on: <K extends string>(
    hookName: K,
    handler: (event: unknown, ctx: unknown) => unknown | Promise<unknown>,
    opts?: { priority?: number; timeoutMs?: number }
  ) => void;
}

function canonicalExistingDirectory(path: unknown): string | null {
  if (typeof path !== 'string' || !isAbsolute(path)) return null;
  try {
    const canonical = realpathSync(path);
    return statSync(canonical).isDirectory() ? canonical : null;
  } catch {
    return null;
  }
}

function configuredWorkspaceRoot(api: OpenClawPluginApi): string | null {
  return canonicalExistingDirectory(api.pluginConfig?.workspaceRoot);
}

const SECRET_KEYS = [
  'password', 'token', 'secret', 'api_key', 'apikey', 'api_secret',
  'auth', 'authorization', 'bearer', 'private_key', 'access_token',
  'refresh_token', 'credential', 'passwd', 'pwd',
];

const ALLOW_DECISIONS = new Set(['allow', 'warn', 'context_only']);

/** Matches Zig `openclaw_status.enforcement_note` intent. */
export const ENFORCEMENT_NOTE =
  'supported install is curl-installed ryk + ryk agents setup openclaw; npm/ClawHub paths are sunset; metadata passes are unprotected; prefer wrapper: ryk run -- openclaw';

/** Standing warning text for metadata/discovery passes where api.on is not live. */
export const UNPROTECTED_NOOP_WARNING =
  `[ryk] unprotected: OpenClaw did not provide a live full-runtime hook registration API, ` +
  `so before_tool_call / after_tool_call hooks will NOT fire and cannot block tools. ` +
  `Prefer wrapper: \`ryk run -- openclaw\` (${ENFORCEMENT_NOTE}).`;

/** Manifest-declared tool invoked by Gateway `tools.invoke` during live health. */
export const INERT_CANARY_TOOL = 'ryk_openclaw_canary';
/** Exact synthetic command recognized by the health canary path. Never executed. */
export const INERT_CANARY_COMMAND = ['rm', '-rf', '/'].join(' ');
/** Fixed prefix returned only after the exact canary is blocked by Ryk. */
export const CANARY_BLOCK_PREFIX = 'RYK_CANARY_BLOCK:';
/** Bound tool-hook input before handing it to a child process. */
export const MAX_HOOK_PAYLOAD_BYTES = 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES = 512;
const CANARY_NONCE_RE = /^[A-Za-z0-9_-]{1,64}$/;

const KNOWN_REGISTRATION_MODES = new Set<OpenClawRegistrationMode>([
  'full',
  'discovery',
  'tool-discovery',
  'setup-only',
  'setup-runtime',
  'cli-metadata',
]);

const UNATTENDED_ENV_KEYS = [
  'RYK_UNATTENDED',
  'RYK_OPENCLAW_UNATTENDED',
  'RYK_NONINTERACTIVE',
  'RYK_CI',
  'CI',
] as const;
const FALSY_ENV_VALUES = new Set(['', '0', 'false', 'no', 'off']);

/** True when an approval cannot safely wait for a human response. */
export function isUnattended(
  environ: Record<string, string | undefined> = process.env
): boolean {
  return UNATTENDED_ENV_KEYS.some((key) => {
    const value = environ[key]?.trim().toLowerCase() ?? '';
    return value.length > 0 && !FALSY_ENV_VALUES.has(value);
  });
}

function redactSecrets(data: unknown, seen = new WeakSet<object>()): unknown {
  if (data === null || data === undefined) return data;
  if (typeof data === 'string') return data;
  if (typeof data === 'bigint') {
    throw new TypeError('BigInt values are not JSON serializable');
  }
  if (typeof data !== 'object') return data;

  if (seen.has(data)) throw new TypeError('cyclic values are not JSON serializable');
  seen.add(data);

  try {
    if (Array.isArray(data)) return data.map((value) => redactSecrets(value, seen));

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      const lowerKey = key.toLowerCase();
      if (SECRET_KEYS.some((s) => lowerKey.includes(s))) {
        result[key] = '[REDACTED]';
      } else {
        result[key] = redactSecrets(value, seen);
      }
    }
    return result;
  } finally {
    seen.delete(data);
  }
}

type TraversalBudget = { nodes: number; stringBytes: number };

class PayloadTooLargeError extends Error {}

function validateJsonSafe(
  data: unknown,
  seen = new WeakSet<object>(),
  depth = 0,
  budget: TraversalBudget = { nodes: 0, stringBytes: 0 }
): void {
  budget.nodes += 1;
  if (budget.nodes > 20_000 || depth > 64) {
    throw new PayloadTooLargeError('payload traversal limit exceeded');
  }
  if (data === null || data === undefined) return;
  if (typeof data === 'string') {
    budget.stringBytes += Buffer.byteLength(data, 'utf8');
    if (budget.stringBytes > MAX_HOOK_PAYLOAD_BYTES) {
      throw new PayloadTooLargeError('payload string limit exceeded');
    }
    return;
  }
  if (typeof data === 'bigint') {
    throw new TypeError('BigInt values are not JSON serializable');
  }
  if (typeof data !== 'object') return;
  if (seen.has(data)) throw new TypeError('cyclic values are not JSON serializable');
  seen.add(data);
  try {
    for (const value of Array.isArray(data)
      ? data
      : Object.values(data as Record<string, unknown>)) {
      validateJsonSafe(value, seen, depth + 1, budget);
    }
  } finally {
    seen.delete(data);
  }
}

function buildPayload(event: string, data: unknown, sessionId?: string): object {
  return {
    version: 1,
    host: 'openclaw',
    event,
    payload: redactSecrets(data),
    session_id: sessionId,
    timestamp: new Date().toISOString(),
  };
}

type EncodedPayload =
  | { ok: true; json: string }
  | { ok: false; reason: 'ryk_payload_unserializable' | 'ryk_payload_too_large'; message: string };

function encodeHookPayload(event: string, data: unknown, sessionId?: string): EncodedPayload {
  let json: string;
  try {
    validateJsonSafe(data);
    json = JSON.stringify(buildPayload(event, data, sessionId));
  } catch (error) {
    if (error instanceof PayloadTooLargeError) {
      return {
        ok: false,
        reason: 'ryk_payload_too_large',
        message: 'ryk tool payload is too large; blocking as a precaution.',
      };
    }
    return {
      ok: false,
      reason: 'ryk_payload_unserializable',
      message: 'ryk could not safely serialize the tool payload; blocking as a precaution.',
    };
  }

  if (Buffer.byteLength(json, 'utf8') > MAX_HOOK_PAYLOAD_BYTES) {
    return {
      ok: false,
      reason: 'ryk_payload_too_large',
      message: 'ryk tool payload is too large; blocking as a precaution.',
    };
  }
  return { ok: true, json };
}

function sanitizeDiagnostic(value: unknown): string {
  const raw = typeof value === 'string' ? value : '';
  const providerTokenPrefix = ['s', 'k', '-'].join('');
  const opaqueTokenPattern = new RegExp(
    `\\b(?:gh[pousr]_[A-Za-z0-9_]+|${providerTokenPrefix}[A-Za-z0-9_-]+)\\b`,
    'g'
  );
  return raw
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [REDACTED]')
    .replace(/\b(password|token|secret|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
    .replace(opaqueTokenPattern, '[REDACTED]')
    .slice(0, MAX_DIAGNOSTIC_BYTES);
}

/**
 * Resolve and attest the ryk binary.
 *
 * Managed installs also require the installer-generated, path-bound SHA-256
 * receipt next to the binary. A workspace override is intentionally limited to
 * development fixtures and is not an installation authenticity claim. This
 * rejects relative paths, workspace/temp/node_modules candidates by default,
 * unsafe POSIX modes/owners, paths outside the managed install roots, and
 * candidates that fail the `ryk version --json` identity probe.
 * PATH lookup is implemented directly so Windows does not depend on `which`.
 */
export function findRyk(cwd?: string, platform: NodeJS.Platform = process.platform): string | null {
  const envBin = process.env.RYK_BIN?.trim();
  if (envBin) {
    if (envBin.includes('/') || envBin.includes('\\')) {
      if (!isAbsolute(envBin)) return null;
      return attestRykCandidate(envBin, cwd, platform) ? canonicalPath(envBin) : null;
    }
    const bin = resolveOnPath(envBin, platform);
    return bin && attestRykCandidate(bin, cwd, platform) ? canonicalPath(bin) : null;
  }

  const pathBin = resolveOnPath('ryk', platform);
  if (pathBin && attestRykCandidate(pathBin, cwd, platform)) return canonicalPath(pathBin);

  // Dev-only workspace fallback. It still requires the identity probe above.
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
      if (attestRykCandidate(p, cwd, platform)) return canonicalPath(p);
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

function isWithin(candidate: string, root: string): boolean {
  const normalizedCandidate = candidate.replaceAll('\\', '/').replace(/\/$/, '');
  const normalizedRoot = root.replaceAll('\\', '/').replace(/\/$/, '');
  return normalizedCandidate === normalizedRoot || normalizedCandidate.startsWith(`${normalizedRoot}/`);
}

function isUntrustedCandidate(path: string, cwd?: string, allowWorkspaceOverride = process.env.RYK_ALLOW_WORKSPACE_BIN === '1'): boolean {
  const canonical = canonicalPath(path).replaceAll('\\', '/');
  if (canonical.includes('/node_modules/.bin/')) return true;

  const workspace = canonicalPath(cwd ?? process.cwd());
  if (isWithin(canonical, workspace)) {
    return !allowWorkspaceOverride;
  }

  const temporaryRoots = new Set([
    canonicalPath(tmpdir()),
    canonicalPath('/tmp'),
    canonicalPath('/private/tmp'),
  ]);
  for (const root of temporaryRoots) {
    if (isWithin(canonical, root)) return true;
  }
  const managedRoots = [
    canonicalPath(resolve(homedir(), '.local', 'bin')),
    canonicalPath(resolve(homedir(), '.ryk', 'bin')),
  ];
  return !managedRoots.some((root) => isWithin(canonical, root));
}

/** Validate the installer-generated path-bound checksum receipt. */
export function installerProvenanceValid(
  binaryPath: string,
  receiptPath = join(resolve(binaryPath, '..'), '.ryk-provenance')
): boolean {
  try {
    const canonical = realpathSync(binaryPath);
    if (lstatSync(receiptPath).isSymbolicLink()) return false;
    if (statSync(receiptPath).size > 4096) return false;
    const fields = new Map<string, string>();
    for (const line of readFileSync(receiptPath, 'utf8').split(/\r?\n/)) {
      if (!line) continue;
      if (!line.includes('=')) {
        if (line !== 'ryk-provenance-v1' || fields.size !== 0) return false;
        continue;
      }
      const separator = line.indexOf('=');
      const key = line.slice(0, separator);
      const value = line.slice(separator + 1);
      if (!value || (key !== 'path' && key !== 'sha256') || fields.has(key)) return false;
      fields.set(key, value);
    }
    if (fields.size !== 2 || fields.get('path') !== canonical) return false;
    const digest = fields.get('sha256') ?? '';
    if (!/^[0-9a-f]{64}$/i.test(digest)) return false;
    const actual = createHash('sha256').update(readFileSync(canonical)).digest('hex');
    return actual === digest.toLowerCase();
  } catch {
    return false;
  }
}

function attestRykCandidate(
  path: string,
  cwd?: string,
  platform: NodeJS.Platform = process.platform,
  allowWorkspaceOverride = process.env.RYK_ALLOW_WORKSPACE_BIN === '1'
): boolean {
  if (!existsSync(path)) return false;
  const canonical = canonicalPath(path);
  if (isUntrustedCandidate(canonical, cwd, allowWorkspaceOverride)) return false;
  try {
    const stat = statSync(canonical);
    if (!stat.isFile()) return false;
    if (platform !== 'win32') {
      if ((stat.mode & 0o111) === 0) return false;
      if ((stat.mode & 0o022) !== 0) return false;
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) return false;
    }
    const workspaceOverride = allowWorkspaceOverride &&
      isWithin(canonical, canonicalPath(cwd ?? process.cwd()));
    if (!workspaceOverride && !installerProvenanceValid(canonical)) return false;
    const output = execFileSync(canonical, ['version', '--json'], {
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

/** Normalize OpenClaw tool events into the envelope ryk hook understands. */
export function normalizeOpenClawToolEvent(event: unknown): Record<string, unknown> {
  const e = (event && typeof event === 'object' ? event : {}) as Record<string, unknown>;
  const params =
    e.params && typeof e.params === 'object'
      ? (e.params as Record<string, unknown>)
      : e.tool_input && typeof e.tool_input === 'object'
        ? (e.tool_input as Record<string, unknown>)
        : {};
  const tool =
    (typeof e.toolName === 'string' && e.toolName) ||
    (typeof e.tool_name === 'string' && e.tool_name) ||
    (typeof e.tool === 'string' && e.tool) ||
    undefined;
  const command =
    (typeof params.command === 'string' && params.command) ||
    (typeof e.command === 'string' && e.command) ||
    undefined;
  const cwd =
    (typeof params.cwd === 'string' && params.cwd) ||
    (typeof params.workdir === 'string' && params.workdir) ||
    (typeof e.cwd === 'string' && e.cwd) ||
    undefined;

  return {
    ...e,
    tool,
    tool_name: tool,
    toolName: tool,
    params,
    command,
    cwd,
  };
}

/** Extract the stable OpenClaw session identity used for ryk audit correlation. */
export function openClawSessionId(ctx: unknown): string | undefined {
  if (!ctx || typeof ctx !== 'object') return undefined;
  const record = ctx as Record<string, unknown>;
  for (const key of ['sessionKey', 'sessionId', 'runId']) {
    if (typeof record[key] === 'string' && record[key].trim()) return record[key].trim();
  }
  return undefined;
}

function failClosedBlock(
  reason: string,
  message: string,
  base: Partial<RykResponse> = {}
): RykResponse {
  return {
    ...base,
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
  base: Partial<RykResponse>,
  options: { unattended?: boolean } = {}
): RykResponse {
  if (decision === 'error') {
    return failClosedBlock(
      'ryk_error_response',
      'ryk returned an error decision; blocking as a precaution.',
      { ...base, message: undefined }
    );
  }
  if (decision === 'block') {
    return {
      ...base,
      decision: 'block',
      risk: base.risk ?? 'high',
      category: base.category ?? 'unknown',
      reason: base.reason,
      message:
        sanitizeDiagnostic(base.message) ||
        sanitizeDiagnostic(base.reason) ||
        'ryk blocked this command.',
    };
  }
  if (decision === 'ask') {
    return failClosedBlock(
      options.unattended ? 'ryk_unattended_ask' : 'ryk_ask_unsupported',
      options.unattended
        ? 'ryk requested approval, but this OpenClaw process is unattended; blocking without waiting.'
        : 'ryk requested interactive approval (ask), but this OpenClaw integration has no verified resumable approval contract; blocking.',
      base
    );
  }
  if (!ALLOW_DECISIONS.has(decision)) {
    return failClosedBlock(
      'ryk_unrecognized_decision',
      `ryk returned unrecognized decision "${decision}"; blocking as a precaution.`,
      base
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
  };
}

/**
 * Parse ryk hook stdout into a decision.
 * Non-blocking: soft-allow on empty/malformed.
 * Blocking: fail closed on empty/whitespace, parse errors, missing/non-string decision,
 * `ask`, and unrecognized decisions. Approval is deliberately not translated
 * into a host-native request until a live, versioned OpenClaw approval contract
 * is available; an unknown host must never receive an unenforced ask.
 */
export function parseHookResponse(
  stdout: string,
  blocking: boolean,
  options: { unattended?: boolean } = {}
): RykResponse {
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

  if (!blocking) {
    return {
      decision: decisionRaw as RykResponse['decision'],
      version: typeof record.version === 'number' ? record.version : undefined,
      risk: record.risk as RykResponse['risk'],
      category: typeof record.category === 'string' ? record.category : undefined,
      reason: typeof record.reason === 'string' ? record.reason : undefined,
      message: typeof record.message === 'string' ? record.message : undefined,
    };
  }

  const normalized = normalizeBlockingDecision(decisionRaw, {
    version: typeof record.version === 'number' ? record.version : undefined,
    risk: record.risk as RykResponse['risk'],
    category: typeof record.category === 'string' ? record.category : undefined,
    reason: typeof record.reason === 'string' ? record.reason : undefined,
    message: typeof record.message === 'string' ? record.message : undefined,
    rule: (record.rule as string | null | undefined) ?? undefined,
  }, options);
  if (decisionRaw === 'block') normalized.verifiedPolicyBlock = true;
  return normalized;
}

async function callRyk(
  rykBin: string,
  event: string,
  data: unknown,
  sessionId: string | undefined,
  blocking: boolean,
  logger: PluginLogger | undefined,
  options: { unattended?: boolean; cwd?: string; allowWorkspaceBinary?: boolean } = {}
): Promise<RykResponse> {
  const payload = encodeHookPayload(event, data, sessionId);
  if (!payload.ok) {
    logger?.error?.(`[ryk] Hook ${event} rejected an unsafe payload (${payload.reason}).`);
    return blocking
      ? failClosedBlock(payload.reason, payload.message)
      : softAllow(payload.reason, 'ryk skipped an unsafe non-blocking payload.');
  }

  // Re-attest the cached executable at use time. Initialization checks alone
  // leave a same-process replacement window between plugin load and a hook.
  if (!attestRykCandidate(rykBin, process.cwd(), process.platform, options.allowWorkspaceBinary)) {
    logger?.error?.(`[ryk] Hook ${event} rejected an untrusted or changed ryk executable.`);
    return blocking
      ? failClosedBlock(
          'ryk_binary_untrusted',
          'ryk executable provenance or identity could not be re-attested; blocking as a precaution.'
        )
      : softAllow(
          'ryk_binary_untrusted',
          'ryk executable provenance or identity could not be re-attested; skipping this non-blocking event.'
        );
  }

  try {
    const stdout = await runRykHookProcess(
      rykBin,
      ['hook', 'openclaw', event],
      payload.json,
      blocking ? 15000 : 10000,
      options.cwd
    );

    return parseHookResponse(stdout, blocking, options);
  } catch {
    logger?.error?.(`[ryk] Hook ${event} failed; child-process details withheld.`);

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

function runRykHookProcess(
  executable: string,
  args: string[],
  input: string,
  timeoutMs: number,
  cwd?: string
): Promise<string> {
  return new Promise((resolvePromise, rejectPromise) => {
    const detached = process.platform !== 'win32';
    const child = spawn(executable, args, {
      detached,
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    let capturedBytes = 0;
    let failure: Error | undefined;
    let killTimer: NodeJS.Timeout | undefined;
    let drainTimer: NodeJS.Timeout | undefined;
    let timeoutTimer: NodeJS.Timeout | undefined;
    let settled = false;

    const killGroup = (signal: NodeJS.Signals): void => {
      try {
        if (detached && child.pid) process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch {
        // Already reaped.
      }
    };

    const destroyPipes = (): void => {
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
    };

    const settle = (error?: Error, stdout?: string): void => {
      if (settled) return;
      settled = true;
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (killTimer) clearTimeout(killTimer);
      if (drainTimer) clearTimeout(drainTimer);
      if (error) {
        destroyPipes();
        rejectPromise(error);
      } else {
        resolvePromise(stdout ?? '');
      }
    };

    const abort = (error: Error): void => {
      if (failure || settled) return;
      failure = error;
      killGroup('SIGTERM');
      killTimer = setTimeout(() => killGroup('SIGKILL'), 250);
      killTimer.unref();
      drainTimer = setTimeout(() => {
        killGroup('SIGKILL');
        settle(failure);
      }, 750);
      drainTimer.unref();
    };
    timeoutTimer = setTimeout(() => abort(new Error('ryk hook timed out')), timeoutMs);
    timeoutTimer.unref();
    const capture = (chunk: Buffer, keep: boolean): void => {
      if (settled) return;
      capturedBytes += chunk.length;
      if (capturedBytes > MAX_HOOK_PAYLOAD_BYTES) {
        abort(new Error('ryk hook output exceeded limit'));
        return;
      }
      if (keep) stdout.push(chunk);
    };
    child.stdout.on('data', (chunk: Buffer) => capture(chunk, true));
    child.stderr.on('data', (chunk: Buffer) => capture(chunk, false));
    child.on('error', (error) => abort(error));
    // A direct child can exit while a descendant retains capture pipes. Kill
    // its dedicated process group, then bound the remaining drain independently
    // so an escaped `setsid()` descendant cannot hold the hook open forever.
    child.on('exit', () => {
      killGroup('SIGKILL');
      if (!settled && !failure) {
        drainTimer = setTimeout(() => abort(new Error('ryk hook pipe drain timed out')), 500);
        drainTimer.unref();
      }
    });
    child.on('close', (code) => {
      killGroup('SIGKILL');
      if (failure) {
        settle(failure);
      } else if (code !== 0) {
        settle(new Error(`ryk hook exited ${String(code)}`));
      } else {
        settle(undefined, Buffer.concat(stdout).toString('utf8'));
      }
    });
    child.stdin.on('error', (error) => abort(error));
    child.stdin.end(input);
  });
}

/**
 * Detect whether api.on is a live runtime registration surface.
 * OpenClaw's current registrationMode is authoritative. Older hosts without
 * that field are untrusted for enforcement and must use the wrapper path.
 */
export function isOnNoop(api: OpenClawPluginApi): boolean {
  if (typeof api.on !== 'function') return true;

  // OpenClaw's current API explicitly reports whether registration is live.
  // Only `full` is a runtime hook path; discovery/setup/metadata passes must
  // never be presented as enforcement.
  if (api.registrationMode !== undefined) return api.registrationMode !== 'full';

  // Legacy OpenClaw versions had no registrationMode. A callable api.on is
  // not proof that it dispatches runtime hooks, so default to unprotected.
  return true;
}

function hasUnknownRegistrationMode(api: OpenClawPluginApi): boolean {
  const mode = api.registrationMode as string | undefined;
  return mode !== undefined && !KNOWN_REGISTRATION_MODES.has(mode as OpenClawRegistrationMode);
}

function registerInertCanaryTool(api: OpenClawPluginApi): boolean {
  if (typeof api.registerTool !== 'function') return false;
  api.registerTool({
    name: INERT_CANARY_TOOL,
    description:
      'Inert Ryk health canary. Accepts a synthetic command for policy dispatch proof but never executes it.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        command: { type: 'string', minLength: 1, maxLength: 256 },
        nonce: { type: 'string', minLength: 1, maxLength: 128 },
        cwd: { type: 'string', minLength: 1, maxLength: 4096 },
      },
      required: ['command', 'nonce', 'cwd'],
    },
    outputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        ok: { type: 'boolean' },
        executed: { type: 'boolean' },
        evidence: { type: 'string' },
      },
      required: ['ok', 'executed', 'evidence'],
    },
    async execute(_id, _params) {
      return {
        content: [{ type: 'text', text: 'Ryk inert OpenClaw canary completed without executing input.' }],
        details: {
          ok: true,
          executed: false,
          evidence: 'inert-tool-executor',
        },
      };
    },
  });
  return true;
}

export default function rykPlugin(api: OpenClawPluginApi): void {
  const cwd = process.cwd();
  const rykBin = findRyk(cwd);
  const { logger } = api;
  const workspaceRoot = configuredWorkspaceRoot(api);
  const allowWorkspaceBinary = process.env.RYK_ALLOW_WORKSPACE_BIN === '1';

  if (typeof api.on !== 'function') {
    logger?.warn?.(
      '[ryk] OpenClaw plugin API does not expose hook registration (api.on). ' +
        'Plugin will not register lifecycle hooks. State: unprotected for hook grade; prefer wrapper: `ryk run -- openclaw`.'
    );
    return;
  }

  const onIsNoop = isOnNoop(api);

  if (onIsNoop) {
    logger?.warn?.(UNPROTECTED_NOOP_WARNING);
    if (hasUnknownRegistrationMode(api)) {
      logger?.warn?.(
        `[ryk] OpenClaw returned an unknown registration mode (${String(api.registrationMode)}); ` +
          'registering a fail-closed veto until the host contract is understood.'
      );
      api.on(
        'before_tool_call',
        async () => ({
          block: true,
          blockReason: 'ryk cannot verify the OpenClaw registration mode; blocking as a precaution.',
        }),
        { timeoutMs: 5_000 }
      );
      return;
    }
    // Registering a veto handler on a non-runtime API would claim fail-closed
    // protection while hooks never fire. Prefer the wrapper path instead.
    if (!rykBin) {
      logger?.warn?.(
        '[ryk] Binary not found in PATH (or RYK_BIN). ' +
          'OpenClaw plugin remains unprotected (hooks are not live); ' +
          'prefer wrapper: `ryk run -- openclaw`.'
      );
    }
    return;
  }

  if (!rykBin) {
    if (!registerInertCanaryTool(api)) {
      logger?.warn?.(
        '[ryk] OpenClaw full runtime does not expose api.registerTool; Gateway dispatcher proof is unavailable.'
      );
    }
    logger?.warn?.(
      '[ryk] Binary not found in PATH (or RYK_BIN). ' +
        'Registering fail-closed before_tool_call vetoes. ' +
        'Install ryk or set RYK_BIN to an absolute path. Prefer wrapper: `ryk run -- openclaw`.'
    );
    // Fail closed only when hooks can actually fire (bundled / real api.on).
    api.on(
      'before_tool_call',
      async () => ({
        block: true,
        blockReason: 'ryk binary not found; blocking as a precaution.',
      }),
      { timeoutMs: 5_000 }
    );
    return;
  }

  logger?.info?.(`[ryk] Plugin loaded. Binary: ${rykBin}`);
  if (!registerInertCanaryTool(api)) {
    logger?.warn?.(
      '[ryk] OpenClaw full runtime does not expose api.registerTool; Gateway dispatcher proof is unavailable.'
    );
  }

  const beforeToolCallHandler = async (
    event: unknown,
    ctx: unknown
  ): Promise<OpenClawBlockResult | void> => {
    const liveWorkspaceRoot = configuredWorkspaceRoot(api);
    if (workspaceRoot === null || liveWorkspaceRoot === null || liveWorkspaceRoot !== workspaceRoot) {
      return {
        block: true,
        blockReason: 'ryk workspace binding is missing or invalid; rerun ryk agents setup openclaw.',
      };
    }
    const normalized = normalizeOpenClawToolEvent(event);
    const response = await callRyk(
      rykBin,
      'tool.before',
      normalized,
      openClawSessionId(ctx) ?? openClawSessionId(event),
      true,
      logger,
      {
        unattended: isUnattended(),
        // Policy discovery is bound to operator-controlled plugin config.
        // Tool parameters remain action data and can never select a policy root.
        cwd: liveWorkspaceRoot,
        allowWorkspaceBinary,
      }
    );

    if (response.decision === 'block') {
      const params = normalized.params as Record<string, unknown>;
      const canaryNonce = params?.nonce;
      const isExactCanary =
        normalized.toolName === INERT_CANARY_TOOL &&
        params?.command === INERT_CANARY_COMMAND &&
        typeof canaryNonce === 'string' &&
        CANARY_NONCE_RE.test(canaryNonce) &&
        typeof params?.cwd === 'string' &&
        canonicalExistingDirectory(params.cwd) === liveWorkspaceRoot;
      if (isExactCanary && response.verifiedPolicyBlock === true) {
        return { block: true, blockReason: `${CANARY_BLOCK_PREFIX}${canaryNonce}` };
      }
      const msg = sanitizeDiagnostic(response.message || response.reason) || 'ryk blocked this command.';
      logger?.error?.(`[ryk] Blocked tool execution: ${msg}`);
      return { block: true, blockReason: msg };
    }

    if (response.decision === 'warn') {
      const msg = sanitizeDiagnostic(response.message || response.reason) || 'policy warning from ryk';
      logger?.warn?.(`[ryk] Warning: ${msg}`);
    }

    // Do not return { params: undefined } — some hosts treat that as a rewrite.
    return;
  };

  api.on('before_tool_call', beforeToolCallHandler, { timeoutMs: 20_000 });

  api.on('session_start', async (event, ctx) => {
    logger?.info?.('[ryk] Plugin ready for session.');
    await callRyk(
      rykBin,
      'session.start',
      { session_id: (event as { sessionId?: string })?.sessionId },
      openClawSessionId(ctx) ?? openClawSessionId(event),
      false,
      logger,
      { allowWorkspaceBinary }
    );
  });

  api.on('after_tool_call', async (event, ctx) => {
    await callRyk(
      rykBin,
      'tool.after',
      normalizeOpenClawToolEvent(event),
      openClawSessionId(ctx) ?? openClawSessionId(event),
      false,
      logger,
      { allowWorkspaceBinary }
    );
  });

  api.on('session_end', async (event, ctx) => {
    await callRyk(
      rykBin,
      'session.end',
      event,
      openClawSessionId(ctx) ?? openClawSessionId(event),
      false,
      logger,
      { allowWorkspaceBinary }
    );
  });
}
