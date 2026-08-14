#!/usr/bin/env node
/**
 * Render an OpenCode-like TUI frame with the ryk block toast.
 * Driven by the real plugin hook (fake ryk binary + recorded showToast).
 * Used for sandbox evidence / screenshots — not a substitute for the live TUI.
 */
import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import rykPlugin from '../dist/index.js';

const WIDTH = 88;
const HEIGHT = 22;
const TOAST_WIDTH = 42;

function stripAnsi(text) {
  return text.replace(/\u001b\[[0-9;]*m/g, '');
}

function visibleLen(text) {
  return stripAnsi(text).length;
}

function padLine(text, width) {
  const extra = width - visibleLen(text);
  return extra > 0 ? text + ' '.repeat(extra) : text;
}

function wrap(text, width) {
  const words = text.split(/\s+/);
  const lines = [];
  let current = '';
  for (const word of words) {
    const next = current ? `${current} ${word}` : word;
    if (next.length > width && current) {
      lines.push(current);
      current = word;
    } else {
      current = next;
    }
  }
  if (current) lines.push(current);
  return lines;
}

function paintToast(screen, toast) {
  const title = toast.title ?? 'ryk blocked';
  const message = String(toast.message ?? '').slice(0, 280);
  const inner = TOAST_WIDTH - 4;
  const msgLines = wrap(message, inner).slice(0, 4);
  const box = [
    `┌${'─'.repeat(TOAST_WIDTH - 2)}┐`,
    `│ ${title.padEnd(inner)} │`,
    `│ ${'─'.repeat(inner)} │`,
    ...msgLines.map((line) => `│ ${line.padEnd(inner)} │`),
    `└${'─'.repeat(TOAST_WIDTH - 2)}┘`,
  ];
  const left = WIDTH - TOAST_WIDTH - 2;
  const top = 1;
  for (let i = 0; i < box.length; i += 1) {
    const row = top + i;
    if (!screen[row]) continue;
    const line = box[i];
    screen[row] = screen[row].slice(0, left) + line + screen[row].slice(left + line.length);
  }
}

function renderFrame(toast) {
  const screen = [];
  screen.push(`╭${'─'.repeat(WIDTH - 2)}╮`);
  screen.push(`│ OpenCode  ·  ryk host plugin${' '.repeat(WIDTH - 32)}│`);
  screen.push(`│${'─'.repeat(WIDTH - 2)}│`);
  for (let i = 0; i < HEIGHT - 6; i += 1) {
    const body =
      i === 2
        ? '  bash  rm -rf /'
        : i === 3
          ? '  ✗  tool.execute.before vetoed by ryk'
          : '';
    screen.push(`│${padLine(body, WIDTH - 2)}│`);
  }
  screen.push(`│${'─'.repeat(WIDTH - 2)}│`);
  screen.push(`│ >  ${' '.repeat(WIDTH - 6)}│`);
  screen.push(`╰${'─'.repeat(WIDTH - 2)}╯`);
  if (toast) paintToast(screen, toast);
  return screen.map((line) => padLine(line, WIDTH)).join('\n');
}

async function main() {
  const directory = await mkdtemp(join(tmpdir(), 'ryk-opencode-toast-visual-'));
  const rykBin = join(directory, 'ryk');
  await writeFile(
    rykBin,
    `#!/bin/sh
if [ "$1" = "version" ] && [ "$2" = "--json" ]; then
  printf '%s\\n' '{"product":"ryk","version":"0.0.0"}'
  exit 0
fi
printf '%s\\n' '{"decision":"block","rule":"core.filesystem:rm-rf-root-home","message":"command blocked by ryk policy"}'
`
  );
  await chmod(rykBin, 0o755);

  const original = {
    PATH: process.env.PATH,
    RYK_BIN: process.env.RYK_BIN,
    RYK_ALLOW_WORKSPACE_BIN: process.env.RYK_ALLOW_WORKSPACE_BIN,
  };
  process.env.PATH = `${directory}:${original.PATH ?? ''}`;
  process.env.RYK_BIN = rykBin;
  process.env.RYK_ALLOW_WORKSPACE_BIN = '1';

  const toasts = [];
  try {
    const plugin = await rykPlugin({
      directory,
      worktree: directory,
      client: {
        tui: {
          showToast: async (options) => {
            toasts.push(options);
            return true;
          },
        },
      },
    });
    const before = plugin['tool.execute.before'];
    let thrown = '';
    try {
      await before(
        { tool: 'bash', sessionID: 'visual-1', callID: 'call-1' },
        { args: { command: 'rm -rf /' } }
      );
    } catch (err) {
      thrown = err instanceof Error ? err.message : String(err);
    }
    const recorded = toasts[0];
    const toast = recorded?.body ?? recorded;
    if (!toast || typeof toast.message !== 'string') {
      throw new Error(`expected toast payload, got ${JSON.stringify(toasts)}`);
    }
    const frame = renderFrame(toast);
    const outDir = process.env.RYK_TOAST_EVIDENCE_DIR
      || join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'artifacts', 'opencode-toast');
    await mkdir(outDir, { recursive: true });
    const evidence = {
      thrown,
      toast,
      sdkShape: recorded?.body ? 'v1-body' : 'flat',
      frame,
    };
    await writeFile(join(outDir, 'toast-visual.txt'), `${frame}\n`);
    await writeFile(join(outDir, 'toast-visual.json'), `${JSON.stringify(evidence, null, 2)}\n`);
    process.stdout.write(`${frame}\n`);
    process.stderr.write(`[ryk] visual toast evidence written to ${outDir}\n`);
    if (!/ryk blocked/i.test(toast.message) || toast.variant !== 'error') {
      process.exitCode = 1;
    }
  } finally {
    process.env.PATH = original.PATH;
    if (original.RYK_BIN === undefined) delete process.env.RYK_BIN;
    else process.env.RYK_BIN = original.RYK_BIN;
    if (original.RYK_ALLOW_WORKSPACE_BIN === undefined) delete process.env.RYK_ALLOW_WORKSPACE_BIN;
    else process.env.RYK_ALLOW_WORKSPACE_BIN = original.RYK_ALLOW_WORKSPACE_BIN;
  }
}

await main();
