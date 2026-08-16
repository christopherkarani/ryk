interface RykResponse {
    version?: number;
    decision: 'allow' | 'block' | 'warn' | 'ask' | 'context_only' | 'error';
    risk?: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
    category?: string;
    reason?: string;
    rule?: string | null;
    message?: string;
    redactions?: Array<{
        field: string;
        reason: string;
    }>;
    host_limitations?: string[];
    /** Internal provenance bit; true only for a parsed Ryk `block` decision. */
    verifiedPolicyBlock?: boolean;
}
interface OpenClawAgentToolResult {
    content: Array<{
        type: 'text';
        text: string;
    }>;
    details: Record<string, unknown>;
}
interface OpenClawAgentTool {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
    outputSchema?: Record<string, unknown>;
    execute: (id: string, params: Record<string, unknown>) => Promise<OpenClawAgentToolResult>;
}
type OpenClawRegistrationMode = 'full' | 'discovery' | 'tool-discovery' | 'setup-only' | 'setup-runtime' | 'cli-metadata';
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
    registerTool?: (tool: OpenClawAgentTool, opts?: {
        optional?: boolean;
    }) => void;
    on: <K extends string>(hookName: K, handler: (event: unknown, ctx: unknown) => unknown | Promise<unknown>, opts?: {
        priority?: number;
        timeoutMs?: number;
    }) => void;
}
/** Matches Zig `openclaw_status.enforcement_note` intent. */
export declare const ENFORCEMENT_NOTE = "supported install is curl-installed ryk + ryk agents setup openclaw; npm/ClawHub paths are sunset; metadata passes are unprotected; prefer wrapper: ryk run -- openclaw";
/** Standing warning text for metadata/discovery passes where api.on is not live. */
export declare const UNPROTECTED_NOOP_WARNING: string;
/** Manifest-declared tool invoked by Gateway `tools.invoke` during live health. */
export declare const INERT_CANARY_TOOL = "ryk_openclaw_canary";
/** Exact synthetic command recognized by the health canary path. Never executed. */
export declare const INERT_CANARY_COMMAND: string;
/** Fixed prefix returned only after the exact canary is blocked by Ryk. */
export declare const CANARY_BLOCK_PREFIX = "RYK_CANARY_BLOCK:";
/** Bound tool-hook input before handing it to a child process. */
export declare const MAX_HOOK_PAYLOAD_BYTES: number;
/** True when an approval cannot safely wait for a human response. */
export declare function isUnattended(environ?: Record<string, string | undefined>): boolean;
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
export declare function findRyk(cwd?: string, platform?: NodeJS.Platform): string | null;
/**
 * Reject untrusted binary locations.
 *
 * Managed install roots (`~/.local/bin`, `~/.ryk/bin`) are allowed before the
 * cwd-within plant check so a legitimate curl install still attests when the
 * process cwd is `$HOME` (or another ancestor of those roots).
 */
export declare function isUntrustedCandidate(path: string, cwd?: string, allowWorkspaceOverride?: boolean): boolean;
/** Validate the installer-generated path-bound checksum receipt. */
export declare function installerProvenanceValid(binaryPath: string, receiptPath?: string): boolean;
export declare function attestRykCandidate(path: string, cwd?: string, platform?: NodeJS.Platform, allowWorkspaceOverride?: boolean): boolean;
/** Normalize OpenClaw tool events into the envelope ryk hook understands. */
export declare function normalizeOpenClawToolEvent(event: unknown): Record<string, unknown>;
/** Extract the stable OpenClaw session identity used for ryk audit correlation. */
export declare function openClawSessionId(ctx: unknown): string | undefined;
/**
 * Parse ryk hook stdout into a decision.
 * Non-blocking: soft-allow on empty/malformed.
 * Blocking: fail closed on empty/whitespace, parse errors, missing/non-string decision,
 * `ask`, and unrecognized decisions. Approval is deliberately not translated
 * into a host-native request until a live, versioned OpenClaw approval contract
 * is available; an unknown host must never receive an unenforced ask.
 */
export declare function parseHookResponse(stdout: string, blocking: boolean, options?: {
    unattended?: boolean;
}): RykResponse;
/**
 * Detect whether api.on is a live runtime registration surface.
 * OpenClaw's current registrationMode is authoritative. Older hosts without
 * that field are untrusted for enforcement and must use the wrapper path.
 */
export declare function isOnNoop(api: OpenClawPluginApi): boolean;
export default function rykPlugin(api: OpenClawPluginApi): void;
export {};
//# sourceMappingURL=index.d.ts.map