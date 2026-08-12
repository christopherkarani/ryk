import assert from 'node:assert/strict';
import { realpathSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import rykPlugin, { findRyk, parseHookResponse } from '../dist/index.js';

const pluginRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

async function withFakeRyk(run, scriptBody, pluginExtras = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-plugin-'));
  const body =
    scriptBody ??
    `
payload=$(cat)
case "$payload" in
  *'"command":"rm -rf'* ) printf '%s\\n' '{"decision":"block","message":"command blocked"}' ;;
  *'"command":"rm'* ) printf '%s\\n' '{"decision":"ask","message":"approval required"}' ;;
  * ) printf '%s\\n' '{"decision":"allow"}' ;;
esac
`;
  const script = `#!/bin/sh
if [ "$1" = "version" ] && [ "$2" = "--json" ]; then
  printf '%s\\n' '{"product":"ryk","version":"0.0.0"}'
  exit 0
fi
  ${body.startsWith('#!/bin/sh\n') ? body.slice('#!/bin/sh\n'.length) : body}`;
  const rykBin = join(directory, 'ryk');
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalRykBin = process.env.RYK_BIN;

  await writeFile(rykBin, script);
  await chmod(rykBin, 0o755);
  process.env.PATH = `${directory}:${originalPath ?? ''}`;
  process.env.RYK_BIN = rykBin;
  process.env.RYK_ALLOW_WORKSPACE_BIN = '1';

  try {
    await run(await rykPlugin({ directory, worktree: directory, ...pluginExtras }));
  } finally {
    process.env.PATH = originalPath;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (originalRykBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalRykBin;
    await rm(directory, { recursive: true, force: true });
  }
}

/** Assert thrown Error.message is a single short tool line (no remediation wall). */
function assertShortBlockThrow(err, contextRe) {
  assert.ok(err instanceof Error, 'must throw Error');
  const msg = err.message;
  assert.ok(!msg.includes('\n'), `throw must be single-line, got: ${JSON.stringify(msg)}`);
  assert.ok(!msg.includes('Recourse:'), `throw must not contain Recourse:, got: ${JSON.stringify(msg)}`);
  assert.ok(!msg.includes('Next:'), `throw must not contain Next:, got: ${JSON.stringify(msg)}`);
  assert.match(msg, /ryk blocked/);
  if (contextRe) assert.match(msg, contextRe);
  assert.ok(msg.length <= 200, `throw should stay short (≤200), got ${msg.length}: ${msg}`);
}

for (const [command, message] of [
  ['rm file.txt', 'approval required'],
  ['rm -r build', 'approval required'],
  ['rm -rf build', 'command blocked'],
]) {
  test(`tool.execute.before blocks ${command}`, async () => {
    await withFakeRyk(async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);

      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command } }
        ),
        (err) => {
          assertShortBlockThrow(err, new RegExp(`ryk blocked tool execution: ${message}`));
          return true;
        }
      );
    });
  });
}

test('permission.ask keeps host ask for ryk ask (approve-and-resume)', async () => {
  await withFakeRyk(async (plugin) => {
    const permissionAsk = plugin['permission.ask'];
    assert.ok(permissionAsk);
    const output = { status: 'ask' };

    await permissionAsk({ sessionID: 'session-1', command: 'rm file.txt' }, output);

    // Native permission UI: ryk ask must not hard-deny without resume.
    assert.equal(output.status, 'ask');
  });
});

test('permission.ask denies ryk block', async () => {
  await withFakeRyk(async (plugin) => {
    const permissionAsk = plugin['permission.ask'];
    assert.ok(permissionAsk);
    const output = { status: 'ask' };

    await permissionAsk({ sessionID: 'session-1', command: 'rm -rf build' }, output);

    assert.equal(output.status, 'deny');
  });
});

test('permission.ask fail-closes unknown decisions', async () => {
  await withFakeRyk(
    async (plugin) => {
      const permissionAsk = plugin['permission.ask'];
      assert.ok(permissionAsk);
      const output = { status: 'ask' };
      await permissionAsk({ sessionID: 'session-1', command: 'echo hi' }, output);
      assert.equal(output.status, 'deny');
    },
    `#!/bin/sh
printf '%s\n' '{"decision":"unexpected","message":"bad decision"}'
`
  );
});

// --- permission.ask hard-deny toast (best-effort; never softens deny) ---

test('permission.ask block toasts error with short message', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const permissionAsk = plugin['permission.ask'];
      assert.ok(permissionAsk);
      const output = { status: 'ask' };
      await permissionAsk({ sessionID: 'session-1', command: 'rm -rf build' }, output);
      assert.equal(output.status, 'deny');
      assert.equal(toasts.length, 1, 'exactly one error toast on permission deny');
      const body = toasts[0]?.body;
      assert.ok(body, 'toast body present');
      assert.equal(body.variant, 'error');
      assert.match(body.title, /ryk/i);
      assert.ok(typeof body.message === 'string' && body.message.length > 0);
      assert.ok(body.message.length <= 280, 'toast message ≤280');
      assert.ok(!body.message.includes('\n'), 'toast message single-line');
      assert.ok(!body.message.includes('Recourse:'), 'no Recourse wall in toast');
      assert.ok(!body.message.includes('Next:'), 'no Next wall in toast');
      assert.match(body.message, /ryk blocked/i);
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","rule":"core.filesystem:rm-rf","message":"command blocked by ryk policy\\nRecourse: operator can run ryk allow-once ABC\\nNext: ryk explain rm","remediation_commands":["ryk allow-once ABC","ryk explain rm"]}'
`,
    {
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    }
  );
});

test('permission.ask error decision toasts error and denies', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const permissionAsk = plugin['permission.ask'];
      assert.ok(permissionAsk);
      const output = { status: 'ask' };
      await permissionAsk({ sessionID: 'session-1', command: 'echo hi' }, output);
      assert.equal(output.status, 'deny');
      assert.equal(toasts.length, 1);
      assert.equal(toasts[0]?.body?.variant, 'error');
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"error","message":"evaluator failed"}'
`,
    {
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    }
  );
});

test('permission.ask deny with throwing toast still denies', async () => {
  await withFakeRyk(
    async (plugin) => {
      const permissionAsk = plugin['permission.ask'];
      assert.ok(permissionAsk);
      const output = { status: 'ask' };
      await permissionAsk({ sessionID: 'session-1', command: 'rm -rf build' }, output);
      assert.equal(output.status, 'deny', 'toast failure must not soften deny');
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`,
    {
      client: {
        tui: {
          showToast: async () => {
            throw new Error('toast transport failed');
          },
        },
      },
    }
  );
});

test('permission.ask deny without showToast still denies', async () => {
  await withFakeRyk(
    async (plugin) => {
      const permissionAsk = plugin['permission.ask'];
      assert.ok(permissionAsk);
      const output = { status: 'ask' };
      await permissionAsk({ sessionID: 'session-1', command: 'rm -rf build' }, output);
      assert.equal(output.status, 'deny');
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`
    // no client — toast optional
  );
});

test('permission.ask warn maps to host ask and may toast warning', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const permissionAsk = plugin['permission.ask'];
      assert.ok(permissionAsk);
      const output = { status: 'ask' };
      await permissionAsk({ sessionID: 'session-1', command: 'echo warn-me' }, output);
      assert.equal(output.status, 'ask', 'warn must not silent-allow or hard-deny');
      assert.equal(toasts.length, 1);
      assert.equal(toasts[0]?.body?.variant, 'warning');
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"warn","message":"soft policy note"}'
`,
    {
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    }
  );
});

test('permission.ask ryk ask toasts warning not error', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const permissionAsk = plugin['permission.ask'];
      assert.ok(permissionAsk);
      const output = { status: 'ask' };
      await permissionAsk({ sessionID: 'session-1', command: 'rm file.txt' }, output);
      assert.equal(output.status, 'ask');
      assert.equal(toasts.length, 1);
      assert.equal(toasts[0]?.body?.variant, 'warning');
    },
    undefined,
    {
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    }
  );
});

test('missing binary permission.ask toasts error and denies', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-plugin-'));
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalRykBin = process.env.RYK_BIN;
  process.env.PATH = directory;
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
  delete process.env.RYK_BIN;
  const toasts = [];
  try {
    const plugin = await rykPlugin({
      directory,
      worktree: directory,
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    });
    const permissionAsk = plugin['permission.ask'];
    assert.ok(permissionAsk);
    const output = { status: 'ask' };
    await permissionAsk({ sessionID: 'session-1', command: 'echo hi' }, output);
    assert.equal(output.status, 'deny');
    assert.equal(toasts.length, 1);
    assert.equal(toasts[0]?.body?.variant, 'error');
    assert.match(
      toasts[0]?.body?.message ?? '',
      /^ryk blocked permission:/,
      'missing-binary toast should use formatShortBlock shape'
    );
  } finally {
    process.env.PATH = originalPath;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (originalRykBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalRykBin;
    await rm(directory, { recursive: true, force: true });
  }
});

test('tool.execute.before still hard-blocks ryk ask (no resume on that path)', async () => {
  await withFakeRyk(async (plugin) => {
    const before = plugin['tool.execute.before'];
    assert.ok(before);
    await assert.rejects(
      before(
        { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
        { args: { command: 'rm file.txt' } }
      ),
      (err) => {
        assertShortBlockThrow(err, /ryk blocked tool execution: approval required/);
        return true;
      }
    );
  });
});

// --- Hard-block presentation: short throw + toast (no Recourse wall) ---

test('hard block throws single-line Error without Recourse/Next wall', async () => {
  // Multi-line CLI message + remediation_commands must not leak into throw.
  // Prefer rule in short line; full wall stays on stderr only.
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'rm -rf /' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked tool execution: core\.filesystem:rm-rf-root-home/);
          assert.ok(
            !err.message.includes('allow-once'),
            'remediation must not appear in throw'
          );
          assert.ok(
            !err.message.includes('destructive'),
            'long policy message must not appear in throw when rule is present'
          );
          return true;
        }
      );
    },
    // Heredoc keeps valid JSON with embedded \\n escapes (real multi-line after parse).
    `#!/bin/sh
cat <<'EOF'
{"decision":"block","rule":"core.filesystem:rm-rf-root-home","message":"command blocked by ryk policy: destructive rm\\nRecourse: operator can run ryk allow-once ABC\\nNext: ryk explain rm","remediation_commands":["ryk allow-once ABC","ryk explain rm"]}
EOF
`
  );
});

test('hard block multi-line message without rule uses first line only', async () => {
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'rm -rf /' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked tool execution: command blocked by ryk policy/);
          assert.ok(!err.message.includes('Recourse:'));
          assert.ok(!err.message.includes('Next:'));
          assert.ok(!err.message.includes('allow-once'));
          return true;
        }
      );
    },
    `#!/bin/sh
cat <<'EOF'
{"decision":"block","message":"command blocked by ryk policy: rm refused\\nRecourse: operator can run ryk allow-once ABC\\nNext: ryk explain rm","remediation_commands":["ryk allow-once ABC"]}
EOF
`
  );
});

test('hard block prefers rule in short throw when present', async () => {
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'rm -rf build' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /core\.filesystem:rm-rf-root-home/);
          return true;
        }
      );
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","rule":"core.filesystem:rm-rf-root-home","message":"long wall\\nRecourse: hide me","reason":"also hide if rule wins"}'
`
  );
});

test('hard block with empty rule/message still identifies ryk block', async () => {
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'echo hi' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked tool execution/);
          return true;
        }
      );
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block"}'
`
  );
});

test('hard block shows toast error before throw when client present', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'rm -rf build' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked/);
          return true;
        }
      );
      assert.equal(toasts.length, 1, 'exactly one error toast on block');
      const body = toasts[0]?.body;
      assert.ok(body, 'toast body present');
      assert.equal(body.variant, 'error');
      assert.ok(body.title && body.title.length <= 40, 'toast title short');
      assert.match(body.title, /ryk/i);
      assert.ok(typeof body.message === 'string' && body.message.length > 0);
      assert.ok(body.message.length <= 280, 'toast message ≤280');
      assert.ok(!body.message.includes('\n'), 'toast message single-line');
      assert.ok(!body.message.includes('Recourse:'));
      assert.ok(!body.message.includes('Next:'));
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked\\nRecourse: no","remediation_commands":["ryk allow-once x"]}'
`,
    {
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    }
  );
});

test('toast failure does not allow tool (still throws short Error)', async () => {
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'rm -rf build' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked/);
          return true;
        }
      );
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`,
    {
      client: {
        tui: {
          showToast: async () => {
            throw new Error('toast transport failed');
          },
        },
      },
    }
  );
});

test('missing toast client still hard-blocks with short throw', async () => {
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'rm -rf build' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked/);
          return true;
        }
      );
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`
    // no client — toast optional
  );
});

test('hard block logs short message to console.error by default', async () => {
  const errors = [];
  const originalError = console.error;
  console.error = (...args) => {
    errors.push(args.map(String).join(' '));
  };
  try {
    await withFakeRyk(
      async (plugin) => {
        const before = plugin['tool.execute.before'];
        assert.ok(before);
        await assert.rejects(
          before(
            { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
            { args: { command: 'rm -rf build' } }
          )
        );
        const joined = errors.join('\n');
        assert.match(joined, /\[ryk\] ryk blocked tool execution:/);
        assert.ok(!joined.includes('Next:'), `default stderr must stay short, got: ${JSON.stringify(joined)}`);
        assert.ok(!joined.includes('Recourse:'), `default stderr must stay short, got: ${JSON.stringify(joined)}`);
      },
      `#!/bin/sh
printf '%s\n' '{"decision":"block","message":"command blocked by ryk policy\nRecourse: operator can run ryk allow-once ABC","remediation_commands":["ryk allow-once ABC"]}'
`
    );
  } finally {
    console.error = originalError;
  }
});

test('hard block with RYK_OPENCODE_VERBOSE logs operator Next detail', async () => {
  const errors = [];
  const originalError = console.error;
  const originalVerbose = process.env.RYK_OPENCODE_VERBOSE;
  console.error = (...args) => {
    errors.push(args.map(String).join(' '));
  };
  process.env.RYK_OPENCODE_VERBOSE = '1';
  try {
    await withFakeRyk(
      async (plugin) => {
        const before = plugin['tool.execute.before'];
        assert.ok(before);
        await assert.rejects(
          before(
            { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
            { args: { command: 'rm -rf build' } }
          ),
          (err) => {
            assert.ok(err instanceof Error);
            assert.ok(!err.message.includes('Next:'), 'throw stays short even with VERBOSE');
            assert.ok(!err.message.includes('allow-once'), 'throw stays short even with VERBOSE');
            return true;
          }
        );
        const joined = errors.join('\n');
        assert.match(joined, /\[ryk\] ryk blocked tool execution:/);
        assert.match(joined, /Next:.*allow-once/, `VERBOSE stderr should include Next, got: ${JSON.stringify(joined)}`);
      },
      `#!/bin/sh
printf '%s\n' '{"decision":"block","message":"command blocked by ryk policy","remediation_commands":["ryk allow-once ABC","ryk explain rm"]}'
`
    );
  } finally {
    console.error = originalError;
    if (originalVerbose === undefined) delete process.env.RYK_OPENCODE_VERBOSE;
    else process.env.RYK_OPENCODE_VERBOSE = originalVerbose;
  }
});

test('warn path does not throw and may toast warning', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await before(
        { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
        { args: { command: 'echo warn-me' } }
      );
      assert.equal(toasts.length, 1);
      assert.equal(toasts[0]?.body?.variant, 'warning');
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"warn","message":"soft policy note"}'
`,
    {
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    }
  );
});

test('command.execute.before block uses short throw + error toast', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const hook = plugin['command.execute.before'];
      assert.ok(hook);
      await assert.rejects(
        hook(
          { command: 'danger', sessionID: 'session-1', arguments: '' },
          { parts: [] }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked command/);
          return true;
        }
      );
      assert.equal(toasts.length, 1);
      assert.equal(toasts[0]?.body?.variant, 'error');
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked\\nRecourse: hide","remediation_commands":["ryk explain x"]}'
`,
    {
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    }
  );
});

test('.env local block uses short throw and error toast', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'read', sessionID: 'session-1', callID: 'call-1' },
          { args: { path: '.env' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /\.env protection/);
          return true;
        }
      );
      assert.equal(toasts.length, 1);
      assert.equal(toasts[0]?.body?.variant, 'error');
    },
    undefined,
    {
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    }
  );
});

test('missing binary hard-block toasts error and throws short message', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-plugin-'));
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalRykBin = process.env.RYK_BIN;
  const originalHome = process.env.HOME;
  process.env.PATH = directory;
  process.env.HOME = directory; // isolate well-known ~/.local/bin lookup
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
  delete process.env.RYK_BIN;
  const toasts = [];
  try {
    const plugin = await rykPlugin({
      directory,
      worktree: directory,
      client: {
        tui: {
          showToast: async (input) => {
            toasts.push(input);
          },
        },
      },
    });
    const before = plugin['tool.execute.before'];
    assert.ok(before);
    await assert.rejects(
      before(
        { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
        { args: { command: 'echo hi' } }
      ),
      (err) => {
        assertShortBlockThrow(err, /ryk binary not found/);
        return true;
      }
    );
    assert.equal(toasts.length, 1);
    assert.equal(toasts[0]?.body?.variant, 'error');
  } finally {
    process.env.PATH = originalPath;
    process.env.HOME = originalHome;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (originalRykBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalRykBin;
    await rm(directory, { recursive: true, force: true });
  }
});

test('ryk.ts is a single-source sync of src/index.ts', async () => {
  const src = await readFile(join(pluginRoot, 'src/index.ts'), 'utf8');
  const dropIn = await readFile(join(pluginRoot, 'ryk.ts'), 'utf8');
  assert.equal(
    dropIn,
    src,
    'ryk.ts must match src/index.ts (npm run build copies src → ryk.ts)'
  );
});

test('package metadata publishes the canonical OpenCode drop-in', async () => {
  const packageJson = JSON.parse(await readFile(join(pluginRoot, 'package.json'), 'utf8'));
  assert.deepEqual(
    packageJson.files.filter((file) => file.endsWith('.ts')),
    ['ryk.ts']
  );
  assert.equal(packageJson.scripts.build, 'tsc -p tsconfig.json && cp src/index.ts ryk.ts');
});

test('missing binary registers fail-closed veto hooks', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-plugin-'));
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalHome = process.env.HOME;
  // Empty PATH + isolated HOME so well-known install lookup also fails.
  process.env.PATH = directory;
  process.env.HOME = directory;
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
  try {
    const plugin = await rykPlugin({ directory, worktree: directory });
    const before = plugin['tool.execute.before'];
    const permissionAsk = plugin['permission.ask'];
    assert.ok(before, 'missing binary must register tool.execute.before veto');
    assert.ok(permissionAsk, 'missing binary must register permission.ask veto');

    await assert.rejects(
      before(
        { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
        { args: { command: 'echo hi' } }
      ),
      /ryk binary not found/
    );

    const output = { status: 'ask' };
    await permissionAsk({ sessionID: 'session-1', command: 'echo hi' }, output);
    assert.equal(output.status, 'deny');
  } finally {
    process.env.PATH = originalPath;
    process.env.HOME = originalHome;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    await rm(directory, { recursive: true, force: true });
  }
});

test('tool.execute.before blocks empty stdout', async () => {
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'echo hi' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked tool execution/);
          return true;
        }
      );
    },
    `#!/bin/sh
# empty stdout
`
  );
});

test('tool.execute.before blocks decision error', async () => {
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'echo hi' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked tool execution: evaluator failed/);
          return true;
        }
      );
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"error","message":"evaluator failed"}'
`
  );
});

test('tool.execute.before blocks unknown decision', async () => {
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'echo hi' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked tool execution/);
          return true;
        }
      );
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"unexpected","message":"bad decision"}'
`
  );
});

test('toast timeout does not prevent hard block throw', async () => {
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      const start = Date.now();
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          { args: { command: 'rm -rf build' } }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked/);
          return true;
        }
      );
      // Toast hangs for 10s; plugin must not wait that long (TOAST_TIMEOUT_MS=1500).
      assert.ok(Date.now() - start < 4000, 'stuck toast must not freeze hard-block path');
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`,
    {
      client: {
        tui: {
          showToast: () => new Promise(() => {}), // never resolves
        },
      },
    }
  );
});

test('findRyk rejects an existing non-ryk absolute RYK_BIN', () => {
  const prevRyk = process.env.RYK_BIN;
  try {
    delete process.env.RYK_BIN;
    process.env.RYK_BIN = process.execPath;
    assert.equal(findRyk(), null);
  } finally {
    if (prevRyk === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = prevRyk;
  }
});

test('findRyk rejects relative path-shaped RYK_BIN', () => {
  const prevRyk = process.env.RYK_BIN;
  try {
    delete process.env.RYK_BIN;
    process.env.RYK_BIN = './zig-out/bin/ryk';
    assert.equal(findRyk(), null);
    process.env.RYK_BIN = 'evil/ryk';
    assert.equal(findRyk(), null);
  } finally {
    if (prevRyk === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = prevRyk;
  }
});

test('findRyk does not shell-interpolate metacharacters in bare RYK_BIN', () => {
  const prevRyk = process.env.RYK_BIN;
  const marker = join(tmpdir(), `opencode-inject-${Date.now()}`);
  try {
    delete process.env.RYK_BIN;
    // Would create marker if interpolated into a shell; argv which must not.
    process.env.RYK_BIN = `ryk; touch ${marker}`;
    assert.equal(findRyk(), null);
    assert.equal(
      (() => {
        try {
          return require('node:fs').existsSync(marker);
        } catch {
          return false;
        }
      })(),
      false
    );
  } finally {
    if (prevRyk === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = prevRyk;
  }
});


test('findRyk accepts product install under HOME workspace', async () => {
  // OpenCode often opens $HOME as the project; ~/.local/bin/ryk must still win.
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-home-ws-'));
  const localBin = join(directory, '.local', 'bin');
  await mkdir(localBin, { recursive: true });
  const rykBin = join(localBin, 'ryk');
  await writeFile(
    rykBin,
    `#!/bin/sh
printf '%s\\n' '{"product":"ryk","version":"1.2.16"}'
`,
    { mode: 0o755 }
  );
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalHome = process.env.HOME;
  const originalBin = process.env.RYK_BIN;
  delete process.env.RYK_BIN;
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
  process.env.HOME = directory;
  process.env.PATH = localBin;
  try {
    assert.equal(findRyk(directory), realpathSync(rykBin));
  } finally {
    process.env.PATH = originalPath;
    process.env.HOME = originalHome;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (originalBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalBin;
    await rm(directory, { recursive: true, force: true });
  }
});

test('findRyk accepts managed ~/.ryk/bin under HOME workspace', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-ryk-bin-'));
  const managedBin = join(directory, '.ryk', 'bin');
  await mkdir(managedBin, { recursive: true });
  const rykBin = join(managedBin, 'ryk');
  await writeFile(
    rykBin,
    `#!/bin/sh
printf '%s\\n' '{"product":"ryk","version":"1.2.16"}'
`,
    { mode: 0o755 }
  );
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalHome = process.env.HOME;
  const originalBin = process.env.RYK_BIN;
  delete process.env.RYK_BIN;
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
  process.env.HOME = directory;
  process.env.PATH = managedBin;
  try {
    assert.equal(findRyk(directory), realpathSync(rykBin));
  } finally {
    process.env.PATH = originalPath;
    process.env.HOME = originalHome;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (originalBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalBin;
    await rm(directory, { recursive: true, force: true });
  }
});

test('findRyk rejects HOME root plant when cwd is HOME', async () => {
  // Non-managed path under $HOME must stay fail-closed (not a denylist gap).
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-home-plant-'));
  const rykBin = join(directory, 'ryk');
  await writeFile(
    rykBin,
    `#!/bin/sh
printf '%s\\n' '{"product":"ryk","version":"1.2.16"}'
`,
    { mode: 0o755 }
  );
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalHome = process.env.HOME;
  const originalBin = process.env.RYK_BIN;
  delete process.env.RYK_BIN;
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
  process.env.HOME = directory;
  process.env.PATH = directory;
  try {
    assert.equal(findRyk(directory), null);
  } finally {
    process.env.PATH = originalPath;
    process.env.HOME = originalHome;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (originalBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalBin;
    await rm(directory, { recursive: true, force: true });
  }
});

test('findRyk rejects workspace bin/ryk plant without allow override', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-bin-plant-'));
  const binDir = join(directory, 'bin');
  await mkdir(binDir, { recursive: true });
  const rykBin = join(binDir, 'ryk');
  await writeFile(
    rykBin,
    `#!/bin/sh
printf '%s\\n' '{"product":"ryk","version":"1.2.16"}'
`,
    { mode: 0o755 }
  );
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalHome = process.env.HOME;
  const originalBin = process.env.RYK_BIN;
  delete process.env.RYK_BIN;
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
  process.env.HOME = join(directory, 'home-isolated');
  process.env.PATH = binDir;
  try {
    assert.equal(findRyk(directory), null);
    process.env.RYK_BIN = rykBin;
    assert.equal(findRyk(directory), null, 'absolute workspace plant via RYK_BIN also rejected');
  } finally {
    process.env.PATH = originalPath;
    process.env.HOME = originalHome;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (originalBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalBin;
    await rm(directory, { recursive: true, force: true });
  }
});

test('findRyk ignores workspace zig-out without RYK_ALLOW_WORKSPACE_BIN', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-plugin-'));
  const zigOutBin = join(directory, 'zig-out', 'bin');
  const rykBin = join(zigOutBin, 'ryk');
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalHome = process.env.HOME;
  await mkdir(zigOutBin, { recursive: true });
  await writeFile(rykBin, '#!/bin/sh\nif [ "$1" = version ] && [ "$2" = --json ]; then printf \'%s\\n\' \'{"product":"ryk","version":"0.0.0"}\'; else echo ok; fi\n');
  await chmod(rykBin, 0o755);
  process.env.PATH = directory; // no ryk on PATH
  process.env.HOME = directory; // isolate well-known install lookup
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
  try {
    assert.equal(findRyk(directory), null);
  } finally {
    process.env.PATH = originalPath;
    process.env.HOME = originalHome;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    await rm(directory, { recursive: true, force: true });
  }
});

test('findRyk accepts workspace zig-out when RYK_ALLOW_WORKSPACE_BIN=1', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-plugin-'));
  const zigOutBin = join(directory, 'zig-out', 'bin');
  // Prefer ryk primary name under workspace allowlist.
  const rykBin = join(zigOutBin, 'ryk');
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalHome = process.env.HOME;
  const prevRyk = process.env.RYK_BIN;
  await mkdir(zigOutBin, { recursive: true });
  await writeFile(
    rykBin,
    '#!/bin/sh\nif [ "$1" = version ] && [ "$2" = --json ]; then\n' +
      '  printf \'%s\\n\' \'{"product":"ryk","version":"0.0.0"}\'\n' +
      'else\n  echo ok\nfi\n'
  );
  await chmod(rykBin, 0o755);
  process.env.PATH = directory;
  process.env.HOME = directory; // no ryk on PATH
  process.env.RYK_ALLOW_WORKSPACE_BIN = '1';
  delete process.env.RYK_BIN;
  try {
    assert.equal(findRyk(directory), realpathSync(rykBin));
  } finally {
    process.env.PATH = originalPath;
    process.env.HOME = originalHome;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (prevRyk === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = prevRyk;
    await rm(directory, { recursive: true, force: true });
  }
});

test('findRyk resolves ryk.exe on a Windows-style PATH', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-plugin-'));
  const rykBin = join(directory, 'ryk.exe');
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalRykBin = process.env.RYK_BIN;
  await writeFile(
    rykBin,
    '#!/bin/sh\nif [ "$1" = version ] && [ "$2" = --json ]; then\n' +
      '  printf \'%s\\n\' \'{"product":"ryk","version":"0.0.0"}\'\n' +
      'fi\n'
  );
  await chmod(rykBin, 0o755);
  process.env.PATH = directory;
  process.env.RYK_ALLOW_WORKSPACE_BIN = '1';
  delete process.env.RYK_BIN;
  try {
    assert.equal(findRyk(directory, 'win32'), realpathSync(rykBin));
  } finally {
    process.env.PATH = originalPath;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (originalRykBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalRykBin;
    await rm(directory, { recursive: true, force: true });
  }
});

test('parseHookResponse empty stdout blocks on blocking path', () => {
  const r = parseHookResponse('', true);
  assert.equal(r.decision, 'block');
  assert.equal(r.reason, 'ryk_empty_response');
});

test('parseHookResponse empty stdout allows on non-blocking path', () => {
  const r = parseHookResponse('', false);
  assert.equal(r.decision, 'allow');
});

test('parseHookResponse error decision blocks on blocking path', () => {
  const r = parseHookResponse(JSON.stringify({ decision: 'error', message: 'boom' }), true);
  assert.equal(r.decision, 'block');
});

test('parseHookResponse unknown decision blocks on blocking path', () => {
  const r = parseHookResponse(JSON.stringify({ decision: 'maybe' }), true);
  assert.equal(r.decision, 'block');
  assert.equal(r.reason, 'ryk_unrecognized_decision');
});

test('parseHookResponse keeps ask on blocking path for permission.ask UX', () => {
  const r = parseHookResponse(JSON.stringify({ decision: 'ask', message: 'need approval' }), true);
  assert.equal(r.decision, 'ask');
});

test('shell.env scrubs secret-looking variables', async () => {
  await withFakeRyk(async (plugin) => {
    const shellEnv = plugin['shell.env'];
    assert.ok(shellEnv);
    const output = {
      env: {
        PATH: '/usr/bin',
        HOME: '/home/dev',
        OPENAI_API_KEY: 'sk-secret',
        GITHUB_TOKEN: 'ghp_secret',
        MY_NORMAL: 'ok',
      },
    };
    await shellEnv({ cwd: '/tmp', sessionID: 's1' }, output);
    assert.equal(output.env.PATH, '/usr/bin');
    assert.equal(output.env.MY_NORMAL, 'ok');
    assert.equal(output.env.OPENAI_API_KEY, undefined);
    assert.equal(output.env.GITHUB_TOKEN, undefined);
  });
});

test('tool.execute.before blocks .env reads locally', async () => {
  await withFakeRyk(async (plugin) => {
    const before = plugin['tool.execute.before'];
    assert.ok(before);
    await assert.rejects(
      before(
        { tool: 'read', sessionID: 'session-1', callID: 'call-1' },
        { args: { path: '.env' } }
      ),
      (err) => {
        assertShortBlockThrow(err, /\.env protection/);
        return true;
      }
    );
  });
});

test('command.execute.before blocks when ryk returns block', async () => {
  await withFakeRyk(
    async (plugin) => {
      const hook = plugin['command.execute.before'];
      assert.ok(hook);
      await assert.rejects(
        hook(
          { command: 'danger', sessionID: 'session-1', arguments: '' },
          { parts: [] }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked command/);
          return true;
        }
      );
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`
  );
});

test('parseHookResponse keeps remediation_commands', () => {
  const r = parseHookResponse(
    JSON.stringify({
      decision: 'block',
      message: 'nope',
      remediation_commands: ['ryk allow-once abc', 'ryk explain "rm"'],
    }),
    true
  );
  assert.equal(r.decision, 'block');
  assert.deepEqual(r.remediation_commands, ['ryk allow-once abc', 'ryk explain "rm"']);
});
