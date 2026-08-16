import assert from 'node:assert/strict';
import { realpathSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import rykPlugin from '../dist/index.js';
import tuiModule from '../dist/tui.js';

// Helpers are attached to the default function. Named function exports would be
// loaded as extra plugins by OpenCode 1.18's legacy loader.
const { findRyk, parseHookResponse } = rykPlugin;


function toastPayload(input) {
  // OpenCode 1.18+ uses flat fields; older clients wrap under body.
  return input?.body ?? input;
}

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
  const unattendedKeys = ['CI', 'RYK_CI', 'RYK_NONINTERACTIVE', 'RYK_UNATTENDED'];
  const savedUnattended = Object.fromEntries(
    unattendedKeys.map((key) => [key, process.env[key]])
  );
  for (const key of unattendedKeys) delete process.env[key];

  try {
    await run(await rykPlugin({ directory, worktree: directory, ...pluginExtras }));
  } finally {
    process.env.PATH = originalPath;
    if (originalAllow === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = originalAllow;
    if (originalRykBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalRykBin;
    for (const key of unattendedKeys) {
      if (savedUnattended[key] === undefined) delete process.env[key];
      else process.env[key] = savedUnattended[key];
    }
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

for (const command of ['rm file.txt', 'rm -r build']) {
  test(`tool.execute.before permits residual ask for ${command}`, async () => {
    await withFakeRyk(async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await before(
        { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
        { args: { command } }
      );
    });
  });
}

test('tool.execute.before blocks rm -rf build', async () => {
  await withFakeRyk(async (plugin) => {
    const before = plugin['tool.execute.before'];
    assert.ok(before);

    await assert.rejects(
      before(
        { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
        { args: { command: 'rm -rf build' } }
      ),
      (err) => {
        assertShortBlockThrow(err, /ryk blocked tool execution: command blocked/);
        return true;
      }
    );
  });
});

test('tool.execute.before unattended residual ask is deny', async () => {
  await withFakeRyk(async (plugin) => {
    process.env.RYK_UNATTENDED = '1';
    const before = plugin['tool.execute.before'];
    await assert.rejects(
      before(
        { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
        { args: { command: 'rm file.txt' } }
      ),
      (err) => {
        assertShortBlockThrow(err, /approval required|ryk blocked/);
        return true;
      }
    );
  });
});

test('permission.ask unattended residual ask is deny', async () => {
  await withFakeRyk(async (plugin) => {
    process.env.RYK_UNATTENDED = '1';
    const permissionAsk = plugin['permission.ask'];
    const output = { status: 'ask' };
    await permissionAsk({ sessionID: 'session-1', command: 'rm file.txt' }, output);
    assert.equal(output.status, 'deny');
  });
});

test('permission.ask permits ryk ask so agents can work', async () => {
  await withFakeRyk(async (plugin) => {
    const permissionAsk = plugin['permission.ask'];
    assert.ok(permissionAsk);
    const output = { status: 'ask' };

    await permissionAsk({ sessionID: 'session-1', command: 'rm file.txt' }, output);

    assert.equal(output.status, 'allow');
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
      const body = toastPayload(toasts[0]);
      assert.ok(body, 'toast payload present');
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
      assert.equal(toastPayload(toasts[0])?.variant, 'error');
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

test('permission.ask warn proceeds without a host ask and may toast warning', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const permissionAsk = plugin['permission.ask'];
      assert.ok(permissionAsk);
      const output = { status: 'ask' };
      await permissionAsk({ sessionID: 'session-1', command: 'echo warn-me' }, output);
      assert.equal(output.status, 'allow', 'warn must not open a host ask');
      assert.equal(toasts.length, 1);
      assert.equal(toastPayload(toasts[0])?.variant, 'warning');
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

test('permission.ask ryk ask permits without toast', async () => {
  const toasts = [];
  await withFakeRyk(
    async (plugin) => {
      const permissionAsk = plugin['permission.ask'];
      assert.ok(permissionAsk);
      const output = { status: 'ask' };
      await permissionAsk({ sessionID: 'session-1', command: 'rm file.txt' }, output);
      assert.equal(output.status, 'allow');
      assert.equal(toasts.length, 0);
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
    assert.equal(toastPayload(toasts[0])?.variant, 'error');
    assert.match(
      toastPayload(toasts[0])?.message ?? '',
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

test('tool.execute.before pins host tool after args.tool (shell not classified as read)', async () => {
  // Model/schema may put `tool: "read"` in args. Flattened payload must still
  // identify bash so shell policy applies (not a README read allow).
  await withFakeRyk(
    async (plugin) => {
      const before = plugin['tool.execute.before'];
      assert.ok(before);
      await assert.rejects(
        before(
          { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
          {
            args: {
              command: 'rm -rf build',
              tool: 'read',
              path: 'README.md',
            },
          }
        ),
        (err) => {
          assertShortBlockThrow(err, /ryk blocked tool execution: command blocked/);
          return true;
        }
      );
    },
    `#!/bin/sh
payload=$(cat)
printf '%s\\n' "$payload" | node -e '
let s = "";
process.stdin.on("data", (d) => { s += d; });
process.stdin.on("end", () => {
  const parsed = JSON.parse(s);
  const tool = parsed && parsed.payload && parsed.payload.tool;
  if (tool === "bash") {
    process.stdout.write("{\\"decision\\":\\"block\\",\\"message\\":\\"command blocked\\"}\\n");
  } else {
    process.stdout.write("{\\"decision\\":\\"allow\\"}\\n");
  }
});
'
`
  );
});

test('tool.execute.before permits residual ryk ask', async () => {
  await withFakeRyk(async (plugin) => {
    const before = plugin['tool.execute.before'];
    assert.ok(before);
    await before(
      { tool: 'bash', sessionID: 'session-1', callID: 'call-1' },
      { args: { command: 'rm file.txt' } }
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

test('OpenCode SDK app.log this._client does not abort plugin load', async () => {
  // Live 1.18.18: pluginLog detached client.app.log → "evaluating 'this._client'"
  // and the server never registered tool.execute.before.
  await withFakeRyk(
    async (plugin) => {
      assert.equal(typeof plugin['tool.execute.before'], 'function');
      const before = plugin['tool.execute.before'];
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
        app: {
          _client: { post: async () => true },
          async log(input) {
            if (!this || !this._client) {
              throw new TypeError("undefined is not an object (evaluating 'this._client')");
            }
            return input;
          },
        },
      },
    }
  );
});

test('OpenCode SDK showToast this._client still delivers a toast', async () => {
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
      assert.equal(toasts.length, 1, 'bound showToast must record a toast');
      const body = toastPayload(toasts[0]);
      assert.equal(body.variant, 'error');
      assert.match(body.message, /ryk blocked/i);
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`,
    {
      client: {
        tui: {
          _client: { post: async () => true },
          async showToast(options) {
            if (!this || !this._client) {
              throw new TypeError("undefined is not an object (evaluating 'this._client')");
            }
            if (options && typeof options === 'object' && options.body?.message) {
              toasts.push(options);
            } else if (options && typeof options.message === 'string') {
              toasts.push(options);
            }
            return true;
          },
        },
      },
    }
  );
});

test('v1 SDK silent-empty showToast still delivers body toast', async () => {
  // Live OpenCode v1 client: showToast({ title, message }) POSTs no body, returns 200.
  // Flat-first + early return is why the TUI never painted "ryk blocked".
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
      assert.equal(toasts.length, 1, 'v1 silent-empty client must still record a body toast');
      const body = toastPayload(toasts[0]);
      assert.equal(body.variant, 'error');
      assert.match(body.title, /ryk/i);
      assert.match(body.message, /ryk blocked/i);
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`,
    {
      client: {
        tui: {
          showToast: async (options) => {
            if (
              options &&
              typeof options === 'object' &&
              options.body &&
              typeof options.body.message === 'string'
            ) {
              toasts.push(options);
            }
            return true;
          },
        },
      },
    }
  );
});

test('v2 SDK flat showToast (arity 2) delivers toast', async () => {
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
      assert.equal(toasts.length, 1, 'v2 flat client must record the toast');
      const body = toastPayload(toasts[0]);
      assert.equal(body.variant, 'error');
      assert.match(body.message, /ryk blocked/i);
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`,
    {
      client: {
        tui: {
          showToast: async (parameters, _options) => {
            if (parameters && typeof parameters.message === 'string') {
              toasts.push(parameters);
              return true;
            }
            return true;
          },
        },
      },
    }
  );
});

test('publish fallback uses tui.toast.show properties envelope', async () => {
  const published = [];
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
      assert.equal(published.length, 1);
      assert.equal(published[0].type, 'tui.toast.show');
      assert.equal(typeof published[0].properties?.message, 'string');
      assert.match(published[0].properties.message, /ryk blocked/i);
      assert.equal(published[0].properties.variant, 'error');
      assert.equal(published[0].message, undefined, 'must not put message on the event root');
    },
    `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`,
    {
      client: {
        tui: {
          publish: async (event) => {
            published.push(event);
          },
        },
      },
    }
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
      const body = toastPayload(toasts[0]);
      assert.ok(body, 'toast payload present');
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

test('hard block does not console.error by default (OpenCode status-line noise)', async () => {
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
        // OpenCode paints console.error as a red TUI status line — keep it quiet by default.
        assert.ok(
          !/\[ryk\] ryk blocked tool execution:/.test(joined),
          `default hard-block must not console.error, got: ${JSON.stringify(joined)}`
        );
        assert.ok(!joined.includes('Next:'), `default stderr must stay quiet, got: ${JSON.stringify(joined)}`);
        assert.ok(!joined.includes('Recourse:'), `default stderr must stay quiet, got: ${JSON.stringify(joined)}`);
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
      assert.equal(toastPayload(toasts[0])?.variant, 'warning');
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
      assert.equal(toastPayload(toasts[0])?.variant, 'error');
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
      assert.equal(toastPayload(toasts[0])?.variant, 'error');
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
    assert.equal(toastPayload(toasts[0])?.variant, 'error');
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

test('package metadata publishes the canonical OpenCode drop-ins', async () => {
  const packageJson = JSON.parse(await readFile(join(pluginRoot, 'package.json'), 'utf8'));
  assert.deepEqual(
    packageJson.files.filter((file) => file.endsWith('.ts')),
    ['ryk.ts', 'ryk-tui.ts']
  );
  assert.equal(
    packageJson.scripts.build,
    'tsc -p tsconfig.json && cp src/index.ts ryk.ts && cp src/tui.ts ryk-tui.ts'
  );
});

test('drop-in has no extra named function exports (OpenCode 1.18 legacy loader)', async () => {
  const mod = await import('../dist/index.js');
  const namedFns = Object.entries(mod)
    .filter(([name, value]) => name !== 'default' && typeof value === 'function')
    .map(([name]) => name);
  assert.deepEqual(namedFns, [], `named function exports become extra plugins: ${namedFns.join(', ')}`);
  assert.equal(typeof mod.default, 'function');
  assert.equal(typeof mod.default.parseHookResponse, 'function');
  assert.equal(typeof mod.default.findRyk, 'function');
});

test('TUI host module is a v1 { id, tui } export', () => {
  assert.equal(tuiModule.id, 'ryk');
  assert.equal(typeof tuiModule.tui, 'function');
  assert.equal(tuiModule.server, undefined);
});

test('TUI host toasts on session.error that mentions ryk', async () => {
  const toasts = [];
  await tuiModule.tui({
    ui: {
      toast: (input) => {
        toasts.push(input);
      },
    },
    event: {
      on: (type, handler) => {
        if (type === 'session.error') {
          handler({ message: '[ryk] ryk blocked tool execution: core.git:push-force-long' });
        }
      },
    },
  });
  assert.ok(toasts.length >= 2, 'startup toast + error toast');
  assert.equal(toasts[0].variant, 'info');
  assert.match(toasts[0].title, /ryk/i);
  assert.equal(toasts[0].message, 'ryk TUI loaded');
  assert.ok(!/guardrails active/i.test(toasts[0].message));
  const errorToast = toasts.find((t) => t.variant === 'error');
  assert.ok(errorToast, 'error toast for ryk session.error');
  assert.match(errorToast.message, /push-force-long/);
});

test('TUI status command uses hook-grade-honest copy', async () => {
  const toasts = [];
  let commands = [];
  await tuiModule.tui({
    ui: {
      toast: (input) => {
        toasts.push(input);
      },
    },
    command: {
      register: (cb) => {
        commands = cb();
      },
    },
  });
  const status = commands.find((c) => c.value === 'ryk.status');
  assert.ok(status, 'ryk.status command registered');
  assert.ok(!/guardrails/i.test(String(status.description ?? '')));
  status.onSelect();
  const statusToast = toasts.find((t) => t.variant === 'info' && t.message !== 'ryk TUI loaded');
  assert.ok(statusToast, 'status toast after onSelect');
  assert.match(statusToast.message, /OpenCode host plugin loaded/i);
  assert.match(statusToast.message, /ryk\.ts/);
  assert.ok(!/guarding this OpenCode session/i.test(statusToast.message));
});

test('TUI does not toast session.error that is only a repo path containing ryk', async () => {
  const toasts = [];
  await tuiModule.tui({
    ui: {
      toast: (input) => {
        toasts.push(input);
      },
    },
    event: {
      on: (type, handler) => {
        if (type === 'session.error') {
          handler({
            message: 'ENOENT: /Users/dev/CodingProjects/ryk/README.md',
          });
        }
      },
    },
  });
  const errorToasts = toasts.filter((t) => t.variant === 'error');
  assert.equal(errorToasts.length, 0, 'path-only ryk must not toast as blocked');
});

test('TUI does not toast error.data or nested properties as ryk blocks', async () => {
  const toasts = [];
  await tuiModule.tui({
    ui: {
      toast: (input) => {
        toasts.push(input);
      },
    },
    event: {
      on: (type, handler) => {
        if (type === 'session.error') {
          handler({
            error: {
              data: '[ryk] ryk blocked leaked payload',
            },
            properties: {
              message: '[ryk] ryk blocked via properties',
            },
          });
        }
      },
    },
  });
  const errorToasts = toasts.filter((t) => t.variant === 'error');
  assert.equal(errorToasts.length, 0, 'must not toast from error.data or properties');
});

test('TUI toasts session.error wrapped in OpenCode { type, properties } envelope', async () => {
  const toasts = [];
  await tuiModule.tui({
    ui: {
      toast: (input) => {
        toasts.push(input);
      },
    },
    event: {
      on: (type, handler) => {
        if (type === 'session.error') {
          handler({
            type: 'session.error',
            properties: {
              error: { message: 'ryk blocked tool execution: core.git:push-force-long' },
            },
          });
        }
      },
    },
  });
  const errorToast = toasts.find((t) => t.variant === 'error');
  assert.ok(errorToast, 'SDK envelope session.error must toast');
  assert.match(errorToast.message, /push-force-long/);
});

test('TUI toasts session.error from error.message only when event.message is absent', async () => {
  const toasts = [];
  await tuiModule.tui({
    ui: {
      toast: (input) => {
        toasts.push(input);
      },
    },
    event: {
      on: (type, handler) => {
        if (type === 'session.error') {
          handler({
            error: { message: 'ryk blocked tool execution: core.git:push-force-long' },
          });
        }
      },
    },
  });
  const errorToast = toasts.find((t) => t.variant === 'error');
  assert.ok(errorToast, 'error.message with ryk blocked still toasts');
  assert.match(errorToast.message, /push-force-long/);
});

test('ryk-tui.ts is a single-source sync of src/tui.ts', async () => {
  const src = await readFile(join(pluginRoot, 'src/tui.ts'), 'utf8');
  const dropIn = await readFile(join(pluginRoot, 'ryk-tui.ts'), 'utf8');
  assert.equal(dropIn, src, 'ryk-tui.ts must match src/tui.ts (npm run build copies src → ryk-tui.ts)');
});

test('missing binary registers fail-closed veto hooks', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-plugin-'));
  const originalPath = process.env.PATH;
  const originalAllow = process.env.RYK_ALLOW_WORKSPACE_BIN;
  const originalHome = process.env.HOME;
  const originalBin = process.env.RYK_BIN;
  // Empty PATH + isolated HOME so well-known install lookup also fails.
  // RYK_BIN must be cleared too — a host install leak would skip fail-closed.
  process.env.PATH = directory;
  process.env.HOME = directory;
  delete process.env.RYK_BIN;
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
    if (originalBin === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = originalBin;
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

test('toast timeout is logged as timeout not as success', async () => {
  const errors = [];
  const originalError = console.error;
  const originalDebug = process.env.RYK_OPENCODE_TOAST_DEBUG;
  console.error = (...args) => {
    errors.push(args.map(String).join(' '));
  };
  process.env.RYK_OPENCODE_TOAST_DEBUG = '1';
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
            assertShortBlockThrow(err, /ryk blocked/);
            return true;
          }
        );
        const joined = errors.join('\n');
        assert.match(joined, /toast timeout/i, `timeout must be distinguishable, got: ${JSON.stringify(joined)}`);
      },
      `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`,
      {
        client: {
          tui: {
            showToast: () => new Promise(() => {}),
          },
        },
      }
    );
  } finally {
    console.error = originalError;
    if (originalDebug === undefined) delete process.env.RYK_OPENCODE_TOAST_DEBUG;
    else process.env.RYK_OPENCODE_TOAST_DEBUG = originalDebug;
  }
});

test('late toast rejection after timeout is not an unhandled rejection', async () => {
  const unhandled = [];
  const onUnhandled = (err) => {
    unhandled.push(err);
  };
  process.on('unhandledRejection', onUnhandled);
  let settleLate;
  const lateFail = new Promise((_, reject) => {
    settleLate = () => reject(new Error('late toast transport failed'));
  });
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
            assertShortBlockThrow(err, /ryk blocked/);
            return true;
          }
        );
        settleLate();
        await new Promise((resolve) => setTimeout(resolve, 50));
        assert.equal(unhandled.length, 0, `late toast reject must be caught, got: ${unhandled}`);
      },
      `#!/bin/sh
printf '%s\\n' '{"decision":"block","message":"command blocked"}'
`,
      {
        client: {
          tui: {
            showToast: () => lateFail,
          },
        },
      }
    );
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
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
  const originalBin = process.env.RYK_BIN;
  await mkdir(zigOutBin, { recursive: true });
  await writeFile(rykBin, '#!/bin/sh\nif [ "$1" = version ] && [ "$2" = --json ]; then printf \'%s\\n\' \'{"product":"ryk","version":"0.0.0"}\'; else echo ok; fi\n');
  await chmod(rykBin, 0o755);
  process.env.PATH = directory; // no ryk on PATH
  process.env.HOME = directory; // isolate well-known install lookup
  delete process.env.RYK_BIN;
  delete process.env.RYK_ALLOW_WORKSPACE_BIN;
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
