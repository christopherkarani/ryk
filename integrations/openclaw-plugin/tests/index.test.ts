import { describe, it, mock } from 'node:test';
import assert from 'node:assert';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import rykPlugin, {
  CANARY_BLOCK_PREFIX,
  attestRykCandidate,
  findRyk,
  installerProvenanceValid,
  INERT_CANARY_TOOL,
  INERT_CANARY_COMMAND,
  isOnNoop,
  isUntrustedCandidate,
  MAX_HOOK_PAYLOAD_BYTES,
  normalizeOpenClawToolEvent,
  parseHookResponse,
  isUnattended,
  openClawSessionId,
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
  const registerTool = mock.fn();
  return {
    id: 'test',
    name: 'test-plugin',
    source: '/bundled/plugins/ryk',
    config: {},
    pluginConfig: { workspaceRoot: process.cwd() },
    runtime: {},
    logger,
    registerTool,
    on,
    registrationMode: 'full',
    ...overrides,
  };
}

function makeFakeRyk(
  hookScript: string,
  parent: string = process.cwd()
): { path: string; cleanup: () => void } {
  const dir = mkdtempSync(join(parent, '.ryk-openclaw-test-'));
  const path = join(dir, 'ryk');
  writeFileSync(
    path,
    `#!/bin/sh\nif [ "$1" = "version" ]; then\n  printf '%s\\n' '{"product":"ryk","version":"1.2.11"}'\n  exit 0\nfi\n${hookScript}\n`,
    { mode: 0o700 }
  );
  chmodSync(path, 0o700);
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function writeProvenance(binary: string): string {
  const receipt = join(binary, '..', '.ryk-provenance');
  const digest = createHash('sha256').update(readFileSync(binary)).digest('hex');
  writeFileSync(receipt, `ryk-provenance-v1\npath=${realpathSync(binary)}\nsha256=${digest}\n`);
  return receipt;
}

function readProbeCount(countFile: string): number {
  if (!existsSync(countFile)) return 0;
  return Number(readFileSync(countFile, 'utf8').trim()) || 0;
}

function makeManagedRyk(hookScript = "printf '%s\\n' '{\"decision\":\"allow\"}'"): {
  path: string;
  dir: string;
  countFile: string;
  receipt: string;
  cleanup: () => void;
} {
  const dir = join(
    homedir(),
    '.local',
    'bin',
    `ryk-openclaw-attest-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`
  );
  mkdirSync(dir, { recursive: true });
  const path = join(dir, 'ryk');
  const countFile = join(dir, 'version-count');
  writeFileSync(
    path,
    `#!/bin/sh\nif [ "$1" = "version" ]; then\n  c=0\n  if [ -f '${countFile}' ]; then c=$(cat '${countFile}'); fi\n  echo $((c + 1)) > '${countFile}'\n  printf '%s\\n' '{"product":"ryk","version":"1.2.11"}'\n  exit 0\nfi\n${hookScript}\n`,
    { mode: 0o700 }
  );
  chmodSync(path, 0o700);
  const receipt = writeProvenance(path);
  return {
    path,
    dir,
    countFile,
    receipt,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function withoutPins<T>(run: () => T): T {
  const previousBin = process.env.RYK_BIN;
  const previousWorkspace = process.env.RYK_ALLOW_WORKSPACE_BIN;
  delete process.env.RYK_BIN;
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
  try {
    return run();
  } finally {
    if (previousBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = previousBin;
    if (previousWorkspace === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = previousWorkspace;
  }
}

function withRykBin<T>(path: string, run: () => T): T {
  const previous = process.env.RYK_BIN;
  const previousWorkspace = process.env.RYK_ALLOW_WORKSPACE_BIN;
  process.env.RYK_BIN = path;
  process.env.RYK_ALLOW_WORKSPACE_BIN = '1';
  try {
    return run();
  } finally {
    if (previous === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = previous;
    if (previousWorkspace === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = previousWorkspace;
  }
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

  it('requires a path-bound checksum receipt for an installed executable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ryk-provenance-'));
    const binary = join(dir, 'ryk');
    const receipt = join(dir, '.ryk-provenance');
    try {
      writeFileSync(binary, 'ryk binary');
      const digest = createHash('sha256').update(readFileSync(binary)).digest('hex');
      writeFileSync(receipt, `ryk-provenance-v1\npath=${realpathSync(binary)}\nsha256=${digest}\n`);
      assert.strictEqual(installerProvenanceValid(binary, receipt), true);
      writeFileSync(receipt, `ryk-provenance-v1\npath=${realpathSync(binary)}\nsha256=${'0'.repeat(64)}\n`);
      assert.strictEqual(installerProvenanceValid(binary, receipt), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects a self-reporting ryk binary planted in the workspace by default', () => {
    const previousBin = process.env.RYK_BIN;
    const previousWorkspace = process.env.RYK_ALLOW_WORKSPACE_BIN;
    const dir = mkdtempSync(join(process.cwd(), '.ryk-openclaw-planted-'));
    const path = join(dir, 'ryk');
    writeFileSync(path, '#!/bin/sh\nprintf \'%s\\n\' \'{"product":"ryk","version":"9.9.9"}\'\n', { mode: 0o700 });
    delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    process.env.RYK_BIN = path;
    try {
      assert.strictEqual(findRyk(process.cwd()), null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      if (previousBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = previousBin;
      if (previousWorkspace === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = previousWorkspace;
    }
  });

  it('allows managed ~/.local/bin before cwd-within reject when cwd is $HOME', () => {
    const managed = join(homedir(), '.local', 'bin', 'ryk');
    assert.strictEqual(
      isUntrustedCandidate(managed, homedir(), false),
      false,
      'curl-installed ryk under ~/.local/bin must remain trusted when cwd is $HOME'
    );
    assert.strictEqual(
      isUntrustedCandidate(managed, homedir(), true),
      false,
      'managed roots stay trusted with workspace override enabled'
    );
    const homePlant = join(homedir(), `.ryk-openclaw-home-plant-${process.pid}`, 'ryk');
    assert.strictEqual(
      isUntrustedCandidate(homePlant, homedir(), false),
      true,
      'non-managed plants under $HOME must still be rejected'
    );
  });

  it('allows managed ~/.ryk/bin before cwd-within reject when cwd is $HOME', () => {
    const managed = join(homedir(), '.ryk', 'bin', 'ryk');
    assert.strictEqual(isUntrustedCandidate(managed, homedir(), false), false);
  });

  it('rejects a self-reporting ryk binary planted in a temporary directory by default', () => {
    const previousBin = process.env.RYK_BIN;
    const previousWorkspace = process.env.RYK_ALLOW_WORKSPACE_BIN;
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"allow\"}'", tmpdir());
    delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    process.env.RYK_BIN = fake.path;
    try {
      assert.strictEqual(findRyk(), null);
    } finally {
      fake.cleanup();
      if (previousBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = previousBin;
      if (previousWorkspace === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = previousWorkspace;
    }
  });

  it('rejects group-writable self-reporting binaries even with the workspace dev override', () => {
    if (process.platform === 'win32') return;
    const previousBin = process.env.RYK_BIN;
    const previousWorkspace = process.env.RYK_ALLOW_WORKSPACE_BIN;
    const dir = mkdtempSync(join(process.cwd(), '.ryk-openclaw-permissions-'));
    const path = join(dir, 'ryk');
    writeFileSync(path, '#!/bin/sh\nprintf \'%s\\n\' \'{"product":"ryk","version":"9.9.9"}\'\n', { mode: 0o720 });
    chmodSync(path, 0o720);
    process.env.RYK_ALLOW_WORKSPACE_BIN = '1';
    process.env.RYK_BIN = path;
    try {
      assert.strictEqual(findRyk(process.cwd()), null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      if (previousBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = previousBin;
      if (previousWorkspace === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = previousWorkspace;
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

  it('treats unknown registration modes like known non-full (warn unprotected, no veto handlers)', () => {
    const api = makeApi({ registrationMode: 'future-runtime' as any });
    rykPlugin(api);
    const beforeCall = (api.on as any).mock.calls.find(
      (c: any) => c.arguments[0] === 'before_tool_call'
    );
    assert.strictEqual(
      beforeCall,
      undefined,
      'unknown modes must not register veto handlers (api.on may be no-op)'
    );
    const warnText = (api.logger.warn as any).mock.calls
      .map((c: any) => String(c.arguments[0]))
      .join('\n');
    assert.match(warnText, /unprotected/i);
    assert.match(warnText, /unknown registration mode/i);
    assert.match(warnText, /ryk run -- openclaw/);
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

  it('ask decision on blocking path is leftover-ask permit', () => {
    const r = parseHookResponse(
      JSON.stringify({ decision: 'ask', reason: 'needs_approval' }),
      true
    );
    assert.strictEqual(r.decision, 'allow');
    assert.strictEqual(r.reason, 'needs_approval');
  });

  it('ask decision is leftover-ask permit and keeps rule provenance', () => {
    const r = parseHookResponse(
      JSON.stringify({ decision: 'ask', reason: 'needs_approval', rule: 'policy.rule' }),
      true,
      {}
    );
    assert.strictEqual(r.decision, 'allow');
    assert.strictEqual(r.rule, 'policy.rule');
    assert.strictEqual(r.reason, 'needs_approval');
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

  it('stage decision is never leftover-ask permit', () => {
    const r = parseHookResponse(
      JSON.stringify({ decision: 'stage', reason: 'staged_write' }),
      true
    );
    assert.strictEqual(r.decision, 'block');
    assert.strictEqual(r.reason, 'ryk_unrecognized_decision');
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

  it('error decisions do not expose secret-bearing messages', () => {
    const secret = 'super_private_value';
    const r = parseHookResponse(
      JSON.stringify({ decision: 'error', message: `token=${secret}` }),
      true
    );
    assert.strictEqual(r.decision, 'block');
    assert.doesNotMatch(String(r.message), new RegExp(secret));
    assert.match(String(r.message), /blocking as a precaution/);
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
  it('registers a manifest-declared inert canary tool whose executor never runs input', async () => {
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"allow\"}'");
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));

      const toolCalls = (api.registerTool as any).mock.calls;
      assert.strictEqual(toolCalls.length, 1);
      const tool = toolCalls[0].arguments[0];
      assert.strictEqual(tool.name, INERT_CANARY_TOOL);

      const dangerous = ['rm', '-rf', '/'].join(' ');
      const result = await tool.execute('canary-call', {
        command: dangerous,
        nonce: 'health-probe',
        cwd: process.cwd(),
      });
      assert.strictEqual(result.details.executed, false);
      assert.strictEqual(result.details.evidence, 'inert-tool-executor');
      assert.doesNotMatch(JSON.stringify(result), new RegExp(dangerous.replaceAll(' ', '\\s+')));
    } finally {
      fake.cleanup();
    }
  });

  it('emits a nonce-bound proof marker only after a genuine Ryk canary block', async () => {
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"block\",\"reason\":\"policy deny\"}'");
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );

      const result = await beforeCall.arguments[1]({
        toolName: INERT_CANARY_TOOL,
        params: { command: INERT_CANARY_COMMAND, nonce: 'health_42', cwd: process.cwd() },
      }, {});
      assert.deepStrictEqual(result, {
        block: true,
        blockReason: `${CANARY_BLOCK_PREFIX}health_42`,
      });
      assert.doesNotMatch(String(result.blockReason), /rm\s+-rf/);
    } finally {
      fake.cleanup();
    }
  });

  it('does not emit canary proof for a generic fail-closed denial', async () => {
    const fake = makeFakeRyk("printf '%s\\n' 'not-json'");
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );

      const result = await beforeCall.arguments[1]({
        toolName: INERT_CANARY_TOOL,
        params: { command: INERT_CANARY_COMMAND, nonce: 'health_42', cwd: process.cwd() },
      }, {});
      assert.strictEqual(result.block, true);
      assert.doesNotMatch(String(result.blockReason), new RegExp(`^${CANARY_BLOCK_PREFIX}`));
    } finally {
      fake.cleanup();
    }
  });

  it('does not emit canary proof for mismatched command or invalid nonce', async () => {
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"block\",\"reason\":\"policy deny\"}'");
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );

      for (const params of [
        { command: 'echo harmless', nonce: 'health_42', cwd: process.cwd() },
        { command: INERT_CANARY_COMMAND, nonce: 'health:42', cwd: process.cwd() },
      ]) {
        const result = await beforeCall.arguments[1]({
          toolName: INERT_CANARY_TOOL,
          params,
        }, {});
        assert.strictEqual(result.block, true);
        assert.doesNotMatch(String(result.blockReason), new RegExp(`^${CANARY_BLOCK_PREFIX}`));
      }
    } finally {
      fake.cleanup();
    }
  });

  it('binds policy discovery to configured workspace instead of tool-supplied cwd', async () => {
    const workspace = mkdtempSync(join(process.cwd(), '.ryk-openclaw-workspace-'));
    const nested = join(workspace, 'nested');
    const marker = join(workspace, 'ryk.cwd');
    mkdirSync(nested);
    const fake = makeFakeRyk(`pwd > '${marker}'\nprintf '%s\\n' '{"decision":"allow"}'`);
    try {
      const api = makeApi({ pluginConfig: { workspaceRoot: workspace } });
      withRykBin(fake.path, () => rykPlugin(api));
      rmSync(marker, { force: true });
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );

      const result = await beforeCall.arguments[1]({
        toolName: 'exec',
        params: { command: 'git status', cwd: nested },
      }, {});
      assert.strictEqual(result, undefined);
      assert.strictEqual(readFileSync(marker, 'utf8').trim(), realpathSync(workspace));

      (api as any).pluginConfig = { workspaceRoot: nested };
      const rebound = await beforeCall.arguments[1]({
        toolName: 'exec',
        params: { command: 'git status', cwd: nested },
      }, {});
      assert.strictEqual(rebound.block, true);
      assert.match(String(rebound.blockReason), /workspace binding/i);
    } finally {
      rmSync(workspace, { recursive: true, force: true });
      fake.cleanup();
    }
  });

  it('fails closed when operator-controlled workspace binding is absent', async () => {
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"allow\"}'");
    try {
      const api = makeApi({ pluginConfig: {} });
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );
      const result = await beforeCall.arguments[1]({
        toolName: 'exec',
        params: { command: 'git status', cwd: process.cwd() },
      }, {});
      assert.strictEqual(result.block, true);
      assert.match(String(result.blockReason), /workspace binding/i);
    } finally {
      fake.cleanup();
    }
  });

  it('re-attests the selected ryk binary before each blocking hook', async () => {
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"allow\"}'");
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );
      assert.strictEqual(await beforeCall.arguments[1]({ toolName: 'exec', params: { command: 'git status' } }, {}), undefined);

      writeFileSync(fake.path, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
      chmodSync(fake.path, 0o700);
      const result = await beforeCall.arguments[1]({ toolName: 'exec', params: { command: 'git status' } }, {});
      assert.strictEqual(result.block, true);
      assert.match(String(result.blockReason), /attest|trust|provenance/i);
    } finally {
      fake.cleanup();
    }
  });

  it('stress-checks 100 safe and 100 risky tool calls in concurrent batches', async () => {
    const fake = makeFakeRyk(
      "payload=$(/bin/cat)\nif printf '%s' \"$payload\" | /usr/bin/grep -q 'rm -rf /'; then\n  printf '%s\\n' '{\"decision\":\"block\",\"reason\":\"policy deny\"}'\nelse\n  printf '%s\\n' '{\"decision\":\"allow\"}'\nfi"
    );
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );
      const requests = [
        ...Array.from({ length: 100 }, () => 'git status'),
        ...Array.from({ length: 100 }, () => 'rm -rf /'),
      ];
      const results: Array<{ block?: boolean } | undefined> = [];
      for (let start = 0; start < requests.length; start += 20) {
        const batch = requests.slice(start, start + 20);
        results.push(...await Promise.all(batch.map((command) =>
          beforeCall.arguments[1]({ toolName: 'exec', params: { command } }, {})
        )));
      }
      assert.ok(results.slice(0, 100).every((result) => result === undefined));
      assert.ok(results.slice(100).every((result) => result?.block === true));
    } finally {
      fake.cleanup();
    }
  });

  it('fails closed without rejecting on cyclic tool payloads', async () => {
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"allow\"}'");
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );
      const params: Record<string, unknown> = { command: 'git status' };
      params.self = params;

      const result = await beforeCall.arguments[1]({ toolName: 'exec', params }, {});
      assert.strictEqual(result.block, true);
      assert.match(String(result.blockReason), /serializ.*payload/i);
    } finally {
      fake.cleanup();
    }
  });

  it('fails closed without rejecting on BigInt tool payloads', async () => {
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"allow\"}'");
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );

      const result = await beforeCall.arguments[1]({
        toolName: 'exec',
        params: { command: 'git status', count: 1n },
      }, {});
      assert.strictEqual(result.block, true);
      assert.match(String(result.blockReason), /serializ.*payload/i);
    } finally {
      fake.cleanup();
    }
  });

  it('fails closed on cyclic and BigInt values even under redacted secret keys', async () => {
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"allow\"}'");
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );
      const cyclic: Record<string, unknown> = {};
      cyclic.self = cyclic;

      for (const params of [{ token: 1n }, { api_secret: cyclic }]) {
        const result = await beforeCall.arguments[1]({ toolName: 'exec', params }, {});
        assert.strictEqual(result.block, true);
        assert.match(String(result.blockReason), /serializ.*payload/i);
      }
    } finally {
      fake.cleanup();
    }
  });

  it('fails closed before spawning ryk for oversized tool payloads', async () => {
    const marker = join(tmpdir(), `ryk-openclaw-spawned-${process.pid}-${Date.now()}`);
    const fake = makeFakeRyk(`touch '${marker}'\nprintf '%s\\n' '{\"decision\":\"allow\"}'`);
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );

      const result = await beforeCall.arguments[1]({
        toolName: 'write',
        params: { content: 'x'.repeat(MAX_HOOK_PAYLOAD_BYTES + 1) },
      }, {});
      assert.strictEqual(result.block, true);
      assert.match(String(result.blockReason), /payload.*large/i);
      assert.strictEqual(existsSync(marker), false);
    } finally {
      rmSync(marker, { force: true });
      fake.cleanup();
    }
  });

  it('does not log secret-bearing child-process errors', async () => {
    const secret = 'super_private_value';
    const fake = makeFakeRyk(`printf '%s\\n' 'token=${secret}' >&2\nexit 1`);
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );

      const result = await beforeCall.arguments[1]({
        toolName: 'exec',
        params: { command: 'git status' },
      }, {});
      assert.strictEqual(result.block, true);
      const logs = (api.logger.error as any).mock.calls
        .map((call: any) => String(call.arguments[0]))
        .join('\n');
      assert.doesNotMatch(logs, new RegExp(secret));
      assert.doesNotMatch(logs, /token=/i);
    } finally {
      fake.cleanup();
    }
  });

  it('redacts secret-bearing policy warnings', async () => {
    const secret = 'super_private_value';
    const fake = makeFakeRyk(`printf '%s\n' '{"decision":"warn","message":"token=${secret}"}'`);
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );
      assert.strictEqual(await beforeCall.arguments[1]({ toolName: 'exec', params: { command: 'git status' } }, {}), undefined);
      const logs = (api.logger.warn as any).mock.calls.map((call: any) => String(call.arguments[0])).join('\n');
      assert.doesNotMatch(logs, new RegExp(secret));
      assert.match(logs, /token=\[REDACTED\]/);
    } finally {
      fake.cleanup();
    }
  });

  it('reaps a pipe-holding descendant after the Ryk parent exits', async () => {
    const marker = join(tmpdir(), `ryk-openclaw-descendant-${process.pid}-${Date.now()}`);
    const fake = makeFakeRyk(`sh -c 'trap "" TERM; sleep 30' & printf '%s' "$!" > '${marker}'; exit 0`);
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );
      const started = Date.now();
      const result = await beforeCall.arguments[1]({ toolName: 'exec', params: { command: 'git status' } }, {});
      assert.strictEqual(result.block, true);
      assert.ok(Date.now() - started < 2_000);
      const pid = Number(readFileSync(marker, 'utf8'));
      assert.throws(() => process.kill(pid, 0));
    } finally {
      rmSync(marker, { force: true });
      fake.cleanup();
    }
  });

  it('bounds a setsid pipe holder after the Ryk parent exits', async () => {
    if (process.platform === 'win32') return;
    const marker = join(tmpdir(), `ryk-openclaw-setsid-${process.pid}-${Date.now()}`);
    const fake = makeFakeRyk(
      `/usr/bin/perl -MPOSIX -e 'my $pid = fork(); die unless defined $pid; if ($pid == 0) { POSIX::setsid(); $SIG{TERM}="IGNORE"; open(my $fh, ">", "${marker}"); print $fh "$$"; close $fh; sleep 30; } else { for (1..100) { last if -e "${marker}"; select undef, undef, undef, 0.01; } exit 0; }'`
    );
    let descendantPid: number | undefined;
    try {
      const api = makeApi();
      withRykBin(fake.path, () => rykPlugin(api));
      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );
      const started = Date.now();
      const result = await Promise.race([
        beforeCall.arguments[1]({ toolName: 'exec', params: { command: 'git status' } }, {}),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error('pipe drain was unbounded')), 2_000)),
      ]);
      assert.strictEqual(result.block, true);
      assert.ok(Date.now() - started < 2_000);
      descendantPid = Number(readFileSync(marker, 'utf8'));
    } finally {
      if (!descendantPid && existsSync(marker)) {
        try { descendantPid = Number(readFileSync(marker, 'utf8')); } catch { /* marker raced cleanup */ }
      }
      if (descendantPid) {
        try { process.kill(descendantPid, 'SIGKILL'); } catch { /* already gone */ }
      }
      rmSync(marker, { force: true });
      fake.cleanup();
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

describe('sticky managed attest', { concurrency: false }, () => {
  it('first managed attest hashes the binary and execs version --json', () => {
    if (process.platform === 'win32') return;
    const fixture = makeManagedRyk();
    try {
      withoutPins(() => {
        writeFileSync(fixture.receipt, `ryk-provenance-v1\npath=${realpathSync(fixture.path)}\nsha256=${'0'.repeat(64)}\n`);
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), false);
        assert.strictEqual(readProbeCount(fixture.countFile), 0);

        writeProvenance(fixture.path);
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
        assert.strictEqual(readProbeCount(fixture.countFile), 1);
      });
    } finally {
      fixture.cleanup();
    }
  });

  it('second attest with unchanged (dev,ino,size,mtime) skips hash and version --json', () => {
    if (process.platform === 'win32') return;
    const fixture = makeManagedRyk();
    try {
      withoutPins(() => {
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
        assert.strictEqual(readProbeCount(fixture.countFile), 1);

        writeFileSync(fixture.receipt, `ryk-provenance-v1\npath=${realpathSync(fixture.path)}\nsha256=${'0'.repeat(64)}\n`);
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
        assert.strictEqual(
          readProbeCount(fixture.countFile),
          1,
          'unchanged managed identity must not re-exec version --json'
        );
      });
    } finally {
      fixture.cleanup();
    }
  });

  it('size change forces a full re-attest', () => {
    if (process.platform === 'win32') return;
    const fixture = makeManagedRyk();
    try {
      withoutPins(() => {
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
        assert.strictEqual(readProbeCount(fixture.countFile), 1);

        const before = statSync(fixture.path);
        writeFileSync(fixture.path, `${readFileSync(fixture.path, 'utf8')}\n# size-bump\n`, { mode: 0o700 });
        chmodSync(fixture.path, 0o700);
        assert.notStrictEqual(statSync(fixture.path).size, before.size);
        writeProvenance(fixture.path);

        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
        assert.strictEqual(readProbeCount(fixture.countFile), 2);
      });
    } finally {
      fixture.cleanup();
    }
  });

  it('mtime change forces a full re-attest', () => {
    if (process.platform === 'win32') return;
    const fixture = makeManagedRyk();
    try {
      withoutPins(() => {
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
        assert.strictEqual(readProbeCount(fixture.countFile), 1);

        const before = statSync(fixture.path);
        utimesSync(fixture.path, before.atime, new Date(before.mtimeMs + 5_000));
        const after = statSync(fixture.path);
        assert.ok(after.mtimeMs !== before.mtimeMs, 'mtime must change to force re-attest');

        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
        assert.strictEqual(readProbeCount(fixture.countFile), 2);
      });
    } finally {
      fixture.cleanup();
    }
  });

  it('does not cache a failed attest for the same identity', () => {
    if (process.platform === 'win32') return;
    const fixture = makeManagedRyk();
    try {
      withoutPins(() => {
        writeFileSync(fixture.receipt, `ryk-provenance-v1\npath=${realpathSync(fixture.path)}\nsha256=${'0'.repeat(64)}\n`);
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), false);
        assert.strictEqual(readProbeCount(fixture.countFile), 0);

        writeProvenance(fixture.path);
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
        assert.strictEqual(readProbeCount(fixture.countFile), 1);
      });
    } finally {
      fixture.cleanup();
    }
  });

  it('workspace override always full-probes version --json', () => {
    if (process.platform === 'win32') return;
    const fake = makeFakeRyk("printf '%s\\n' '{\"decision\":\"allow\"}'");
    const countFile = join(fake.path, '..', 'version-count');
    writeFileSync(
      fake.path,
      `#!/bin/sh\nif [ "$1" = "version" ]; then\n  c=0\n  if [ -f '${countFile}' ]; then c=$(cat '${countFile}'); fi\n  echo $((c + 1)) > '${countFile}'\n  printf '%s\\n' '{"product":"ryk","version":"1.2.11"}'\n  exit 0\nfi\nprintf '%s\\n' '{"decision":"allow"}'\n`,
      { mode: 0o700 }
    );
    chmodSync(fake.path, 0o700);
    const previousAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
    const previousBin = process.env.RYK_BIN;
    try {
      process.env.RYK_ALLOW_WORKSPACE_BIN = '1';
      delete process.env.RYK_BIN;
      assert.strictEqual(attestRykCandidate(fake.path, process.cwd(), process.platform, true), true);
      assert.strictEqual(attestRykCandidate(fake.path, process.cwd(), process.platform, true), true);
      assert.strictEqual(readProbeCount(countFile), 2);
    } finally {
      if (previousAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = previousAllow;
      if (previousBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = previousBin;
      fake.cleanup();
    }
  });

  it('RYK_ALLOW_WORKSPACE_BIN on a managed path always full-probes', () => {
    if (process.platform === 'win32') return;
    const fixture = makeManagedRyk();
    const previousAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
    const previousBin = process.env.RYK_BIN;
    try {
      delete process.env.RYK_BIN;
      process.env.RYK_ALLOW_WORKSPACE_BIN = '1';
      assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, true), true);
      assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, true), true);
      assert.strictEqual(readProbeCount(fixture.countFile), 2);
    } finally {
      if (previousAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = previousAllow;
      if (previousBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = previousBin;
      fixture.cleanup();
    }
  });

  it('RYK_BIN pin always full-probes and never sticks a managed success', () => {
    if (process.platform === 'win32') return;
    const fixture = makeManagedRyk();
    const previousAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
    const previousBin = process.env.RYK_BIN;
    try {
      delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      process.env.RYK_BIN = fixture.path;
      assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
      assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
      assert.strictEqual(readProbeCount(fixture.countFile), 2);

      writeFileSync(fixture.receipt, `ryk-provenance-v1\npath=${realpathSync(fixture.path)}\nsha256=${'0'.repeat(64)}\n`);
      assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), false);
      assert.strictEqual(readProbeCount(fixture.countFile), 2);
    } finally {
      if (previousAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = previousAllow;
      if (previousBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = previousBin;
      fixture.cleanup();
    }
  });

  it('re-checks mode and uid on every call after a sticky managed success', () => {
    if (process.platform === 'win32') return;
    const fixture = makeManagedRyk();
    try {
      withoutPins(() => {
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), true);
        assert.strictEqual(readProbeCount(fixture.countFile), 1);

        chmodSync(fixture.path, 0o722);
        assert.strictEqual(attestRykCandidate(fixture.path, process.cwd(), process.platform, false), false);
        assert.strictEqual(readProbeCount(fixture.countFile), 1);
      });
    } finally {
      fixture.cleanup();
    }
  });

  it('callRyk still re-attests path/mode every hook while skipping version after managed success', async () => {
    if (process.platform === 'win32') return;
    const fixture = makeManagedRyk();
    const previousPath = process.env.PATH;
    const previousBin = process.env.RYK_BIN;
    const previousAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
    try {
      delete process.env.RYK_BIN;
      delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      process.env.PATH = `${fixture.dir}${delimiter}${previousPath ?? ''}`;

      const api = makeApi();
      rykPlugin(api);
      assert.strictEqual(readProbeCount(fixture.countFile), 1);

      const beforeCall = (api.on as any).mock.calls.find(
        (call: any) => call.arguments[0] === 'before_tool_call'
      );
      assert.strictEqual(
        await beforeCall.arguments[1]({ toolName: 'exec', params: { command: 'git status' } }, {}),
        undefined
      );
      assert.strictEqual(readProbeCount(fixture.countFile), 1);

      chmodSync(fixture.path, 0o722);
      const result = await beforeCall.arguments[1](
        { toolName: 'exec', params: { command: 'git status' } },
        {}
      );
      assert.strictEqual(result.block, true);
      assert.match(String(result.blockReason), /attest|trust|provenance/i);
    } finally {
      process.env.PATH = previousPath;
      if (previousBin === undefined) delete process.env.RYK_BIN;
      else process.env.RYK_BIN = previousBin;
      if (previousAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
      else process.env.RYK_ALLOW_WORKSPACE_BIN = previousAllow;
      fixture.cleanup();
    }
  });
});
