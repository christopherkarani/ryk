/**
 * OpenCode 1.18 TUI host entry.
 *
 * Server hooks live in ryk.ts (default function). This file is a separate
 * module because a v1 plugin cannot export both `server` and `tui`.
 * Vanilla OpenCode lists plugins by `id` from this object — without it the
 * host never shows up and blocks only appear as thrown text in the prompt.
 */

type ToastVariant = 'info' | 'success' | 'warning' | 'error';

type TuiToast = {
  variant?: ToastVariant;
  title?: string;
  message: string;
  duration?: number;
};

type TuiPluginApi = {
  ui?: {
    toast?: (input: TuiToast) => void;
  };
  event?: {
    on?: (type: string, handler: (event: Record<string, unknown>) => void) => (() => void) | void;
  };
  command?: {
    register?: (cb: () => Array<Record<string, unknown>>) => () => void;
  };
};

function firstLine(text: string): string {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed) return trimmed;
  }
  return '';
}

function errorText(event: Record<string, unknown>): string {
  const direct = event.message;
  if (typeof direct === 'string' && direct.trim()) return direct;

  const error = event.error;
  if (typeof error === 'string' && error.trim()) return error;
  if (error && typeof error === 'object') {
    const rec = error as Record<string, unknown>;
    for (const key of ['message', 'data', 'name']) {
      const value = rec[key];
      if (typeof value === 'string' && value.trim()) return value;
    }
  }

  const properties = event.properties;
  if (properties && typeof properties === 'object') {
    return errorText(properties as Record<string, unknown>);
  }
  return '';
}

function looksLikeRyk(text: string): boolean {
  return /ryk/i.test(text);
}

async function rykTui(api: TuiPluginApi): Promise<void> {
  const toast = api.ui?.toast;
  if (typeof toast === 'function') {
    toast({
      variant: 'info',
      title: 'ryk',
      message: 'Guardrails active',
      duration: 2500,
    });
  }

  api.event?.on?.('session.error', (event) => {
    const text = firstLine(errorText(event));
    if (!text || !looksLikeRyk(text)) return;
    if (typeof toast !== 'function') return;
    toast({
      variant: 'error',
      title: 'ryk blocked',
      message: text.slice(0, 280),
      duration: 8000,
    });
  });

  api.command?.register?.(() => [
    {
      title: 'ryk: status',
      value: 'ryk.status',
      category: 'ryk',
      description: 'Show that ryk guardrails are active in this session',
      onSelect: () => {
        if (typeof toast !== 'function') return;
        toast({
          variant: 'info',
          title: 'ryk',
          message: 'Policy hooks are guarding this OpenCode session',
          duration: 4000,
        });
      },
    },
  ]);
}

export default {
  id: 'ryk',
  tui: rykTui,
};
