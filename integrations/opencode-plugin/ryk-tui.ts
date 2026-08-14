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

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

/**
 * OpenCode TUI `event.on` delivers `{ type, properties }`. Tests and older
 * buses pass a flat payload. Only unwrap when `type` is present so a sibling
 * `properties.message` on a flat error object is not treated as the toast.
 */
function eventPayload(event: Record<string, unknown>): Record<string, unknown> {
  if (typeof event.type === 'string') {
    return asRecord(event.properties) ?? asRecord(event.data) ?? event;
  }
  return event;
}

function messageFromUnknown(value: unknown): string {
  if (typeof value === 'string' && value.trim()) return value;
  const rec = asRecord(value);
  if (!rec) return '';
  if (typeof rec.message === 'string' && rec.message.trim()) return rec.message;
  return '';
}

function errorText(event: Record<string, unknown>): string {
  const payload = eventPayload(event);
  const direct = messageFromUnknown(payload.message) || messageFromUnknown(event.message);
  if (direct) return direct;
  return messageFromUnknown(payload.error) || messageFromUnknown(event.error);
}

function looksLikeRyk(text: string): boolean {
  const line = firstLine(text);
  return /^\[ryk\]/i.test(line) || /ryk blocked/i.test(line);
}

async function rykTui(api: TuiPluginApi): Promise<void> {
  const toast = api.ui?.toast;
  if (typeof toast === 'function') {
    toast({
      variant: 'info',
      title: 'ryk',
      message: 'ryk TUI loaded',
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
      description: 'Show that the ryk TUI host plugin is loaded',
      onSelect: () => {
        if (typeof toast !== 'function') return;
        toast({
          variant: 'info',
          title: 'ryk',
          message: 'OpenCode host plugin loaded — policy hooks live in ryk.ts',
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
