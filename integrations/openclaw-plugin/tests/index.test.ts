import { describe, it, mock } from 'node:test';
import assert from 'node:assert';
import { readFile } from 'node:fs/promises';
import rykPlugin, {
  findRyk,
  isOnNoop,
  normalizeOpenClawToolEvent,
  parseHookResponse,
  isUnattended,
  openClawSessionId,
  LIVE_PROBE_METHOD,
  UNPROTECTED_NOOP_WARNING,
} from '../src/index.ts';

// Minimal mock API factory
function makeApi(overrides: Partial<Parameters<typeof rykPlugin>[0]> = {}) {
  const logger = {
    debug: mock.fn(),
    info: mock.fn(),
    warn: mock.fn(),
    error: mock.fn(),
  };
  const on = mock.fn();
  const registerGatewayMethod = mock.fn();
  return {
    id: 'test',
    name: 'test-plugin',
    source: '/bundled/plugins/ryk',
    config: {},
    runtime: {},
    logger,
    registerGatewayMethod,
    on,
    registrationMode: 'full',
    ...overrides,
  };
}

describe('findRyk', () => {
  it('rejects relative RYK_BIN paths (agent-plantable)', () => {
    const prevBin = process.env.RYK_BIN;
    const prevAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
    delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    try {
      process.env.RYK_BIN = './zig-out/bin/ryk';
      assert.strictEqual(findRyk(process.cwd()), null);

      process.env.RYK_BIN = 'evil/ryk';
      assert.strictEqual(findRyk(process.cwd()), null);
    } finally {
      if (prevBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = prevBin;
      if (prevAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = prevAllow;
    }
  });

  it('rejects an existing non-ryk absolute RYK_BIN', () => {
    const prevBin = process.env.RYK_BIN;
    try {
      process.env.RYK_BIN = process.execPath;
      assert.strictEqual(findRyk(), null);
    } finally {
      if (prevBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = prevBin;
    }
  });

  it('returns null for absolute RYK_BIN that does not exist', () => {
    const prevBin = process.env.RYK_BIN;
    try {
      process.env.RYK_BIN = '/tmp/ryk-definitely-missing-deadbeef';
      assert.strictEqual(findRyk(), null);
    } finally {
      if (prevBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = prevBin;
    }
  });

  it('publishes the canonical OpenClaw plugin id', async () => {
    const manifest = JSON.parse(
      await readFile(new URL('../openclaw.plugin.json', import.meta.url), 'utf8')
    );
    assert.strictEqual(manifest.id, 'ryk');
    assert.strictEqual(manifest.name, 'ryk');
  });
});

describe('isOnNoop', () => {
  it('returns true when api.on is not a function', () => {
    const api = makeApi({ on: undefined as unknown as typeof makeApi extends (...args: any[]) => infer R ? R extends { on: infer O } ? O : never : never });
    assert.strictEqual(isOnNoop(api as any), true);
  });

  it('uses full registration mode when the plugin lives under node_modules', () => {
    const api = makeApi({ source: '/path/to/node_modules/ryk-openclaw-plugin' });
    assert.strictEqual(isOnNoop(api), false);
  });

  it('returns true for cli-metadata registration mode', () => {
    const api = makeApi({
      source: '/home/user/.openclaw/npm/ryk-openclaw-plugin',
      registrationMode: 'cli-metadata',
    });
    assert.strictEqual(isOnNoop(api), true);
  });

  it('returns true for discovery registration mode', () => {
    const api = makeApi({ registrationMode: 'discovery' });
    assert.strictEqual(isOnNoop(api), true);
  });

  it('treats legacy APIs without registrationMode as unprotected', () => {
    const api = makeApi({
      source: '/home/user/.openclaw/npm/ryk-openclaw-plugin',
      registrationMode: undefined,
    });
    assert.strictEqual(isOnNoop(api), true);
  });

  it('does not trust bundled sources without an explicit runtime mode', () => {
    const api = makeApi({ source: '/Applications/OpenClaw.app/Contents/Plugins/ryk', registrationMode: undefined });
    assert.strictEqual(isOnNoop(api), true);
  });

  it('does not trust an empty source without an explicit runtime mode', () => {
    const api = makeApi({ source: '', registrationMode: undefined });
    assert.strictEqual(isOnNoop(api), true);
  });

  it('keeps unknown registration modes fail-closed instead of silently unprotected', async () => {
    const api = makeApi({ registrationMode: 'future-runtime' as any });
    rykPlugin(api);
    const beforeCall = (api.on as any).mock.calls.find(
      (c: any) => c.arguments[0] === 'before_tool_call'
    );
    assert.ok(beforeCall, 'unknown modes must receive a fail-closed veto');
    const result = await beforeCall.arguments[1]();
    assert.strictEqual(result.block, true);
    assert.match(String(result.blockReason), /registration mode/);
  });
});

describe('parseHookResponse (fail-closed blocking path)', () => {
  it('empty stdout on blocking path → block', () => {
    const r = parseHookResponse('', true);
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.reason, 'ryk_empty_response');
  });

  it('whitespace-only stdout on blocking path → block', () => {
    const r = parseHookResponse('   \n\t  ', true);
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.reason, 'ryk_empty_response');
  });

  it('malformed JSON on blocking path → block', () => {
    const r = parseHookResponse('{not-json', true);
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.reason, 'ryk_parse_error');
  });

  it('missing decision on blocking path → block', () => {
    const r = parseHookResponse(JSON.stringify({ version: 1 }), true);
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.reason, 'ryk_missing_decision');
  });

  it('non-string decision on blocking path → block', () => {
    const r = parseHookResponse(JSON.stringify({ decision: 42 }), true);
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.reason, 'ryk_missing_decision');
  });

  it('ask decision on blocking path → block', () => {
    const r = parseHookResponse(
      JSON.stringify({ decision: 'ask', reason: 'needs_approval' }),
      true
    );
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.reason, 'ryk_ask_unsupported');
  });

  it('ask decision blocks until a live resumable approval contract is verified', () => {
    const r = parseHookResponse(
      JSON.stringify({ decision: 'ask', reason: 'needs_approval', rule: 'policy.rule' }),
      true,
      {}
    );
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.rule, 'policy.rule');
    assert.strictEqual(r.reason, 'ryk_ask_unsupported');
  });

  it('ask decision blocks immediately in unattended mode', () => {
    const r = parseHookResponse(
      JSON.stringify({ decision: 'ask', reason: 'needs_approval' }),
      true,
      { unattended: true }
    );
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.reason, 'ryk_unattended_ask');
  });

  it('unrecognized decision on blocking path → block', () => {
    const r = parseHookResponse(
      JSON.stringify({ decision: 'maybe', reason: 'weird' }),
      true
    );
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.reason, 'ryk_unrecognized_decision');
  });

  it('allow decision passes through', () => {
    const r = parseHookResponse(
      JSON.stringify({ decision: 'allow', reason: 'policy_allow' }),
      true
    );
    assert.strictEqual(r.decision, 'allow');
  });

  it('block decision passes through', () => {
    const r = parseHookResponse(
      JSON.stringify({ decision: 'block', reason: 'policy_deny', message: 'nope' }),
      true
    );
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.message, 'nope');
  });

  it('empty stdout on non-blocking path → allow', () => {
    const r = parseHookResponse('', false);
    assert.strictEqual(r.decision, 'allow');
  });
});

describe('normalizeOpenClawToolEvent', () => {
  it('maps toolName + params.command into ryk shell envelope', () => {
    const n = normalizeOpenClawToolEvent({
      toolName: 'exec',
      params: { command: 'git status', cwd: '/tmp' },
    });
    assert.strictEqual(n.tool, 'exec');
    assert.strictEqual(n.tool_name, 'exec');
    assert.strictEqual(n.command, 'git status');
    assert.strictEqual(n.cwd, '/tmp');
  });
});

describe('unattended helpers', () => {
  it('recognizes explicit unattended environment signals', () => {
    assert.strictEqual(isUnattended({ RYK_UNATTENDED: '1' }), true);
    assert.strictEqual(isUnattended({ RYK_OPENCLAW_UNATTENDED: 'true' }), true);
    assert.strictEqual(isUnattended({ RYK_UNATTENDED: '0', CI: 'false' }), false);
  });

  it('prefers OpenClaw sessionKey for ryk session correlation', () => {
    assert.strictEqual(
      openClawSessionId({ sessionKey: 'agent:main:hermes', sessionId: 'session-1' }),
      'agent:main:hermes'
    );
    assert.strictEqual(openClawSessionId({ runId: 'run-1' }), 'run-1');
    assert.strictEqual(openClawSessionId(undefined), undefined);
  });

});

describe('rykPlugin', () => {
  it('registers a live deny-canary probe on the full runtime path', () => {
    const prevBin = process.env.RYK_BIN;
    const prevAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
    process.env.RYK_BIN = `${process.cwd()}/zig-out/bin/ryk`;
    process.env.RYK_ALLOW_WORKSPACE_BIN = '1';
    try {
      const api = makeApi();
      rykPlugin(api);
      const gatewayCalls = (api.registerGatewayMethod as any).mock.calls;
      assert.strictEqual(gatewayCalls.length, 1);
      assert.strictEqual(gatewayCalls[0].arguments[0], LIVE_PROBE_METHOD);
    } finally {
      if (prevBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = prevBin;
      if (prevAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = prevAllow;
    }
  });

  it('warns about unprotected cli-metadata api.on', () => {
    const api = makeApi({
      source: '/path/to/node_modules/ryk-openclaw-plugin',
      registrationMode: 'cli-metadata',
    });
    rykPlugin(api);

    const warnCalls = (api.logger.warn as any).mock.calls;
    const noopWarning = warnCalls.find(
      (c: any) =>
        typeof c.arguments[0] === 'string' &&
        (c.arguments[0].includes('unprotected') ||
          c.arguments[0] === UNPROTECTED_NOOP_WARNING)
    );
    assert.ok(noopWarning, 'Expected unprotected warning about noop api.on');
    assert.ok(
      String(noopWarning.arguments[0]).includes('unprotected'),
      'Warning must include unprotected grade label'
    );
    assert.ok(
      String(noopWarning.arguments[0]).includes('ryk run -- openclaw'),
      'Warning must recommend wrapper path'
    );
  });

  it('does not warn about noop when source is bundled', () => {
    const api = makeApi({
      source: '/Applications/OpenClaw.app/Contents/Plugins/ryk',
    });
    rykPlugin(api);

    const warnCalls = (api.logger.warn as any).mock.calls;
    const noopWarning = warnCalls.find(
      (c: any) =>
        typeof c.arguments[0] === 'string' &&
        c.arguments[0].includes('unprotected')
    );
    assert.strictEqual(noopWarning, undefined, 'Should not warn unprotected for bundled installs');
  });

  it('registers fail-closed before_tool_call when binary is missing on a real hook API', async () => {
    const prevBin = process.env.RYK_BIN;
    const prevAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
    delete process.env.RYK_BIN;
    delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    // Force PATH miss by using a name that won't exist if which is used...
    // findRyk uses only the canonical ryk binary name. Prefer RYK_BIN pointing at a missing path.
    process.env.RYK_BIN = '/tmp/ryk-definitely-missing-deadbeef';

    try {
      // Bundled source: api.on is real; missing binary must veto tools.
      const api = makeApi({
        source: '/Applications/OpenClaw.app/Contents/Plugins/ryk',
      });
      rykPlugin(api);

      const onCalls = (api.on as any).mock.calls;
      const events = onCalls.map((c: any) => c.arguments[0]);
      assert.ok(events.includes('before_tool_call'));
      // Missing binary: only the veto hook is required.
      assert.ok(!events.includes('session_start') || events.includes('before_tool_call'));

      const beforeCall = onCalls.find((c: any) => c.arguments[0] === 'before_tool_call');
      assert.ok(beforeCall, 'before_tool_call must be registered');
      const handler = beforeCall.arguments[1] as () => Promise<{ block?: boolean; blockReason?: string }>;
      const result = await handler();
      assert.strictEqual(result.block, true);
      assert.ok(
        String(result.blockReason).includes('not found'),
        'missing binary must veto tools'
      );
    } finally {
      if (prevBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = prevBin;
      if (prevAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = prevAllow;
    }
  });

  it('does not register no-op veto handlers for cli-metadata when binary is missing', () => {
    const prevBin = process.env.RYK_BIN;
    const prevAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
    process.env.RYK_BIN = '/tmp/ryk-definitely-missing-deadbeef';
    delete process.env.RYK_ALLOW_WORKSPACE_BIN;

    try {
      const api = makeApi({
        source: '/path/to/node_modules/ryk-openclaw-plugin',
        registrationMode: 'cli-metadata',
      });
      rykPlugin(api);

      const onCalls = (api.on as any).mock.calls;
      assert.strictEqual(
        onCalls.length,
        0,
        'cli-metadata api.on must not register handlers that claim fail-closed protection'
      );
      const warnCalls = (api.logger.warn as any).mock.calls;
      const unprotected = warnCalls.find(
        (c: any) =>
          typeof c.arguments[0] === 'string' && c.arguments[0].includes('unprotected')
      );
      assert.ok(unprotected, 'must still warn that npm path is unprotected');
    } finally {
      if (prevBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = prevBin;
      if (prevAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = prevAllow;
    }
  });

  it('does not register lifecycle hooks for cli-metadata when binary resolves', () => {
    // A metadata inspection pass must not claim enforcement, even if a binary exists.
    const api = makeApi({
      source: '/path/to/node_modules/ryk-openclaw-plugin',
      registrationMode: 'cli-metadata',
    });
    // Ensure binary appears present so we exercise the binary-present branch.
    const prevBin = process.env.RYK_BIN;
    process.env.RYK_BIN = process.execPath; // any existing absolute path
    try {
      rykPlugin(api);
      const onCalls = (api.on as any).mock.calls;
      assert.strictEqual(
        onCalls.length,
        0,
        'cli-metadata path must not register lifecycle hooks'
      );
    } finally {
      if (prevBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = prevBin;
    }
  });
});
