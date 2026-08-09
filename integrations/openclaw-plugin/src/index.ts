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
}

interface OpenClawBlockResult {
  block?: boolean;
  blockReason?: string;
}

interface OpenClawGatewayRequest {
  params?: unknown;
  respond: (ok: boolean, payload?: unknown, error?: unknown) => void;
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
  registerGatewayMethod?: (
    method: string,
    handler: (request: OpenClawGatewayRequest) => unknown | Promise<unknown>,
    opts?: { scope?: string }
  ) => void;
  on: <K extends string>(
    hookName: K,
    handler: (event: unknown, ctx: unknown) => unknown | Promise<unknown>,
    opts?: { priority?: number; timeoutMs?: number }
  ) => void;
}

const SECRET_KEYS = [
  'password', 'token', 'secret', 'api_key', 'apikey', 'api_secret',
  'auth', 'authorization', 'bearer', 'private_key', 'access_token',
  'refresh_token', 'credential', 'passwd', 'pwd',
];

const ALLOW_DECISIONS = new Set(['allow', 'warn', 'context_only']);

/** Matches Zig `openclaw_status.enforcement_note` intent. */
export const ENFORCEMENT_NOTE =
  'supported install is curl-installed ryk + ryk unattended setup; npm/ClawHub paths are sunset; metadata passes are unprotected; prefer wrapper: ryk run -- openclaw';

/** Standing warning text for metadata/discovery passes where api.on is not live. */
export const UNPROTECTED_NOOP_WARNING =
  `[ryk] unprotected: OpenClaw did not provide a live full-runtime hook registration API, ` +
  `so before_tool_call / after_tool_call hooks will NOT fire and cannot block tools. ` +
  `Prefer wrapper: \`ryk run -- openclaw\` (${ENFORCEMENT_NOTE}).`;

/** Gateway RPC used by unattended health to prove the active plugin registry. */
export const LIVE_PROBE_METHOD = 'ryk.unattended';
const LIVE_PROBE_COMMAND = ['rm', '-rf', '/'].join(' ');

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

/**
 * Resolve and attest the ryk binary.
 *
 * A path is not an authority: a workspace `node_modules/.bin/ryk`, a renamed
 * binary, or an explicit `RYK_BIN` can all be planted by the agent. Candidates
 * must therefore answer the canonical `ryk version --json` identity probe with
 * product `ryk` and a semver version. Workspace candidates remain opt-in for
 * development only. PATH lookup is implemented directly so Windows does not
 * depend on the Unix-only `which` command.
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

  return normalizeBlockingDecision(decisionRaw, {
    version: typeof record.version === 'number' ? record.version : undefined,
    risk: record.risk as RykResponse['risk'],
    category: typeof record.category === 'string' ? record.category : undefined,
    reason: typeof record.reason === 'string' ? record.reason : undefined,
    message: typeof record.message === 'string' ? record.message : undefined,
    rule: (record.rule as string | null | undefined) ?? undefined,
  }, options);
}

async function callRyk(
  rykBin: string,
  event: string,
  data: unknown,
  sessionId: string | undefined,
  blocking: boolean,
  logger: PluginLogger | undefined,
  options: { unattended?: boolean } = {}
): Promise<RykResponse> {
  const payload = buildPayload(event, data, sessionId);
  const payloadJson = JSON.stringify(payload);

  try {
    // argv array — no shell interpolation of rykBin
    const stdout = execFileSync(
      rykBin,
      ['hook', 'openclaw', event],
      {
        input: payloadJson,
        encoding: 'utf-8',
        timeout: blocking ? 15000 : 10000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }
    );

    return parseHookResponse(stdout, blocking, options);
  } catch (err: unknown) {
    const safeErr = redactSecrets({ message: (err as Error).message });
    logger?.error?.(`[ryk] Hook ${event} failed: ${(safeErr as { message: string }).message}`);

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

export default function rykPlugin(api: OpenClawPluginApi): void {
  const cwd = process.cwd();
  const rykBin = findRyk(cwd);
  const { logger } = api;

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

  const beforeToolCallHandler = async (
    event: unknown,
    ctx: unknown
  ): Promise<OpenClawBlockResult | void> => {
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
      }
    );

    if (response.decision === 'block') {
      const msg = response.message || response.reason || 'ryk blocked this command.';
      logger?.error?.(`[ryk] Blocked tool execution: ${msg}`);
      return { block: true, blockReason: msg };
    }

    if (response.decision === 'warn') {
      logger?.warn?.(`[ryk] Warning: ${response.message || response.reason}`);
    }

    // Do not return { params: undefined } — some hosts treat that as a rewrite.
    return;
  };

  api.on('before_tool_call', beforeToolCallHandler, { timeoutMs: 20_000 });

  if (typeof api.registerGatewayMethod === 'function') {
    api.registerGatewayMethod(
      LIVE_PROBE_METHOD,
      async ({ respond }) => {
        const denyCanary = await beforeToolCallHandler(
          {
            toolName: 'bash',
            params: { command: LIVE_PROBE_COMMAND },
          },
          { sessionKey: 'ryk-unattended-health-probe' }
        );
        respond(true, {
          ok: true,
          plugin: 'ryk',
          hook: 'before_tool_call',
          registration: 'full-runtime',
          enforcement: denyCanary?.block === true ? 'deny-canary-pass' : 'deny-canary-fail',
        });
      },
      { scope: 'operator.read' }
    );
  } else {
    logger?.warn?.(
      '[ryk] OpenClaw full runtime has no Gateway probe registration API; ' +
        'unattended health cannot verify the active plugin registry.'
    );
  }

  api.on('session_start', async (event, ctx) => {
    logger?.info?.('[ryk] Plugin ready for session.');
    await callRyk(
      rykBin,
      'session.start',
      { session_id: (event as { sessionId?: string })?.sessionId },
      openClawSessionId(ctx) ?? openClawSessionId(event),
      false,
      logger
    );
  });

  api.on('after_tool_call', async (event, ctx) => {
    await callRyk(
      rykBin,
      'tool.after',
      normalizeOpenClawToolEvent(event),
      openClawSessionId(ctx) ?? openClawSessionId(event),
      false,
      logger
    );
  });

  api.on('session_end', async (event, ctx) => {
    await callRyk(
      rykBin,
      'session.end',
      event,
      openClawSessionId(ctx) ?? openClawSessionId(event),
      false,
      logger
    );
  });
}
