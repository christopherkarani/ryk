//! Minimal shell/command bypass classifiers for Zig command evaluation paths.
//! When `effects:` is active, these merge into command decisions.
//! Host shell PreToolUse is owned by in-process Zig `shell_engine` (not a Rust daemon).

const std = @import("std");
const catalog = @import("catalog.zig");
const ids = @import("ids.zig");
const network_tags = @import("network_tags.zig");

pub fn freeCurlLikeHosts(allocator: std.mem.Allocator, hosts: [][]const u8) void {
    for (hosts) |h| allocator.free(h);
    allocator.free(hosts);
}

/// Transfer hosts from curl/wget operands (allocator-owned unique list).
/// Reused by effect classification and the shell_eval destination allowlist fence.
/// `error.UnreadableCurlConfig` when `--config`/`-K` has no inline URL (cannot parse file).
pub fn extractCurlLikeHosts(allocator: std.mem.Allocator, command_text: []const u8) ![][]const u8 {
    var hosts: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (hosts.items) |h| allocator.free(h);
        hosts.deinit(allocator);
    }
    var opaque_config = false;
    try appendCurlLikeHosts(allocator, command_text, &hosts, &opaque_config, 0);
    if (opaque_config) return error.UnreadableCurlConfig;
    return try hosts.toOwnedSlice(allocator);
}

/// Classify a command display string into effect hits (owned slice).
pub fn classifyCommand(allocator: std.mem.Allocator, command_text: []const u8) ![]catalog.EffectHit {
    var hits: std.ArrayList(catalog.EffectHit) = .empty;
    errdefer hits.deinit(allocator);

    const trimmed = std.mem.trim(u8, command_text, " \t\r\n");
    if (trimmed.len == 0) return try hits.toOwnedSlice(allocator);

    if (try matchesMailtoOpen(allocator, trimmed)) {
        try hits.append(allocator, .{
            .id = "comms.message",
            .confidence = .medium,
            .matcher = "shell_bypass.comms.message.mailto",
        });
    }

    // curl/wget: inspect every URL / tagged host operand (not only the first).
    try appendCurlLikeHostEffects(allocator, trimmed, &hits);

    if (try matchesOsascriptMessages(allocator, trimmed)) {
        if (!hasEffectId(hits.items, "comms.message")) {
            try hits.append(allocator, .{
                .id = "comms.message",
                .confidence = .medium,
                .matcher = "shell_bypass.comms.message.osascript_messages",
            });
        }
    }

    for (hits.items) |hit| {
        std.debug.assert(ids.isKnownEffectId(hit.id));
    }
    return try hits.toOwnedSlice(allocator);
}

fn hasEffectId(hits: []const catalog.EffectHit, id: []const u8) bool {
    for (hits) |h| {
        if (std.mem.eql(u8, h.id, id)) return true;
    }
    return false;
}

fn appendCurlHostHit(
    allocator: std.mem.Allocator,
    hits: *std.ArrayList(catalog.EffectHit),
    host: []const u8,
) !void {
    const tag = network_tags.effectForHost(host) orelse return;
    if (hasEffectId(hits.items, tag.effect_id)) return;
    const matcher: []const u8 = if (std.mem.eql(u8, tag.effect_id, "comms.publish"))
        "shell_bypass.comms.publish.curl_host"
    else if (std.mem.eql(u8, tag.effect_id, "comms.message"))
        "shell_bypass.comms.message.curl_host"
    else
        "shell_bypass.unknown.external.curl_host";
    try hits.append(allocator, .{
        .id = tag.effect_id,
        .confidence = .medium,
        .matcher = matcher,
    });
}

/// `open` / `/usr/bin/open` in command position with a following `mailto:` operand.
fn matchesMailtoOpen(allocator: std.mem.Allocator, command_text: []const u8) !bool {
    const tokens = try tokenizeSimple(allocator, command_text);
    defer allocator.free(tokens);
    if (tokens.len < 2) return false;

    var i: usize = 0;
    while (i + 1 < tokens.len) : (i += 1) {
        if (!isOpenToken(tokens[i])) continue;
        if (!isCommandPosition(tokens, i)) continue;

        // Walk past macOS `open` options (including value-taking flags like -a/-b).
        var j = i + 1;
        while (j < tokens.len) {
            if (isShellOperator(tokens[j])) break;
            const t = tokens[j];
            if (t.len > 0 and t[0] == '-') {
                if (openFlagConsumesNext(t)) {
                    j += 1; // flag
                    if (j < tokens.len and !isShellOperator(tokens[j]) and !(tokens[j].len > 0 and tokens[j][0] == '-')) {
                        j += 1; // option value (e.g. Mail)
                    }
                    continue;
                }
                j += 1; // boolean flag
                continue;
            }
            return startsWithIgnoreCase(t, "mailto:");
        }
    }
    return false;
}

/// macOS `open` flags that take a following value argument.
fn openFlagConsumesNext(token: []const u8) bool {
    return std.mem.eql(u8, token, "-a") or
        std.mem.eql(u8, token, "-b") or
        std.mem.eql(u8, token, "-s") or
        std.mem.eql(u8, token, "--args");
}

fn isOpenToken(token: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(token, "open")) return true;
    if (std.mem.lastIndexOfScalar(u8, token, '/')) |slash| {
        return std.ascii.eqlIgnoreCase(token[slash + 1 ..], "open");
    }
    return false;
}

fn isCurlLikeToken(token: []const u8) bool {
    return isCurlToken(token) or isWgetToken(token);
}

fn isCurlToken(token: []const u8) bool {
    return std.ascii.eqlIgnoreCase(token, "curl") or endsWithIgnoreCase(token, "/curl");
}

fn isWgetToken(token: []const u8) bool {
    return std.ascii.eqlIgnoreCase(token, "wget") or endsWithIgnoreCase(token, "/wget");
}

/// True when `index` is the first executable of a shell command segment:
/// start of segment, after `;`/`|`/`&&`/`||`/`&`, after env assignments, after
/// common wrappers (`sudo`, `env`, `command`, `xargs`, `nohup`, `nice`, `time`),
/// or after wrapper option flags/values (`sudo -u root curl …`, `env -i open …`).
/// Lookup-only `command -v`/`-V` does not count as execution.
fn isCommandPosition(tokens: []const []const u8, index: usize) bool {
    if (index == 0) return true;
    // Walk left through env assignments, wrappers, and their option tokens.
    var i = index;
    while (i > 0) {
        const prev = tokens[i - 1];
        if (isShellOperator(prev)) return true;
        if (isEnvAssignment(prev)) {
            i -= 1;
            continue;
        }
        if (isCommandWrapper(prev)) {
            // Bash `command -v`/`-V` describes a name; it does not execute it.
            if (isCommandBuiltinLookup(tokens, i - 1, index)) return false;
            i -= 1;
            continue;
        }
        if (prev.len > 0 and prev[0] == '-') {
            i -= 1;
            continue;
        }
        // Value after a value-taking wrapper flag (e.g. `-u` → `root` before `curl`).
        if (i >= 2) {
            const maybe_flag = tokens[i - 2];
            if (maybe_flag.len > 0 and maybe_flag[0] == '-' and wrapperFlagTakesValue(maybe_flag)) {
                i -= 1;
                continue;
            }
        }
        return false;
    }
    return true;
}

/// True when `tokens[wrapper_index]` is the `command` builtin used with `-v`/`-V`
/// between the builtin and the candidate executable at `exec_index`.
fn isCommandBuiltinLookup(tokens: []const []const u8, wrapper_index: usize, exec_index: usize) bool {
    if (wrapper_index >= tokens.len or wrapper_index >= exec_index) return false;
    var base = tokens[wrapper_index];
    if (std.mem.lastIndexOfScalar(u8, base, '/')) |slash| base = base[slash + 1 ..];
    if (!std.ascii.eqlIgnoreCase(base, "command")) return false;

    var j = wrapper_index + 1;
    while (j < exec_index) : (j += 1) {
        const t = tokens[j];
        if (std.mem.eql(u8, t, "-v") or std.mem.eql(u8, t, "-V")) return true;
    }
    return false;
}

/// Known wrapper flags that take a following value (conservative; used when walking left).
/// Boolean wrapper flags (`-n`, `-i`, `-E`, …) are skipped via the generic `-` branch.
fn wrapperFlagTakesValue(flag: []const u8) bool {
    // `--name=value` is a single token; no following value to skip.
    if (std.mem.startsWith(u8, flag, "--") and std.mem.indexOfScalar(u8, flag, '=') != null) return false;
    const value_flags = [_][]const u8{
        // sudo
        "-u",             "--user",     "-g",          "--group",
        "-h",             "--host",     "-C",          "--close-from",
        "-D",             "--chdir",    "-p",          "--prompt",
        "-r",             "--role",     "-T",          "--type",
        "--other-user",
        // env
          "-u",         "--unset",     "-S",
        "--split-string", "-C",         "--chdir",
        // nice / time (common)
            "-n",
        "--adjustment",   "-f",         "-o",
        // xargs
                 "-a",
        "--arg-file",     "-d",         "--delimiter", "-E",
        "-e",             "--eof",      "-I",          "-i",
        "--replace",      "-L",         "-l",          "--max-lines",
        "-n",             "--max-args", "-P",          "--max-procs",
        "-R",             "-s",         "--max-chars",
    };
    for (value_flags) |name| {
        if (std.mem.eql(u8, flag, name)) return true;
    }
    return false;
}

fn isEnvAssignment(token: []const u8) bool {
    // FOO=bar (simple shell assignment; not PATH-style with /).
    if (token.len < 2) return false;
    const eq = std.mem.indexOfScalar(u8, token, '=') orelse return false;
    if (eq == 0) return false;
    for (token[0..eq]) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_')) return false;
    }
    return true;
}

fn isCommandWrapper(token: []const u8) bool {
    // Launchers that run a following COMMAND (not mere data operands).
    const wrappers = [_][]const u8{ "sudo", "env", "command", "xargs", "nohup", "nice", "time", "builtin", "exec" };
    // Strip path prefix: /usr/bin/sudo
    var base = token;
    if (std.mem.lastIndexOfScalar(u8, token, '/')) |slash| base = token[slash + 1 ..];
    for (wrappers) |w| {
        if (std.ascii.eqlIgnoreCase(base, w)) return true;
    }
    return false;
}

fn isShellOperator(token: []const u8) bool {
    return std.mem.eql(u8, token, ";") or
        std.mem.eql(u8, token, "|") or
        std.mem.eql(u8, token, "&&") or
        std.mem.eql(u8, token, "||") or
        std.mem.eql(u8, token, "&");
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

fn matchesOsascriptMessages(allocator: std.mem.Allocator, command_text: []const u8) !bool {
    const tokens = try tokenizeSimple(allocator, command_text);
    defer allocator.free(tokens);
    var has_osascript = false;
    var has_messages = false;
    for (tokens) |t| {
        if (std.ascii.eqlIgnoreCase(t, "osascript") or endsWithIgnoreCase(t, "/osascript")) {
            has_osascript = true;
        }
        if (std.ascii.eqlIgnoreCase(t, "messages") or indexOfIgnoreCase(t, "messages") != null) {
            has_messages = true;
        }
    }
    return has_osascript and has_messages;
}

fn endsWithIgnoreCase(haystack: []const u8, suffix: []const u8) bool {
    if (haystack.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[haystack.len - suffix.len ..], suffix);
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or haystack.len < needle.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

/// Whitespace tokenizer with quote stripping; also emits shell operators as tokens
/// and splits attached operators (e.g. `decoy;` → `decoy`, `;`).
/// Exhaustive: every token in `command_text` is returned (no silent 48-token cap).
fn tokenizeSimple(allocator: std.mem.Allocator, command_text: []const u8) ![][]const u8 {
    var tokens: std.ArrayList([]const u8) = .empty;
    errdefer tokens.deinit(allocator);
    var i: usize = 0;
    while (i < command_text.len) {
        while (i < command_text.len and isSpace(command_text[i])) : (i += 1) {}
        if (i >= command_text.len) break;

        if (command_text[i] == '\'' or command_text[i] == '"') {
            const quote = command_text[i];
            i += 1;
            const start = i;
            while (i < command_text.len and command_text[i] != quote) : (i += 1) {}
            try tokens.append(allocator, command_text[start..i]);
            if (i < command_text.len) i += 1;
            continue;
        }

        // Shell operators as their own tokens (including && and ||).
        if (try tryEmitOperator(allocator, command_text, &i, &tokens)) continue;

        const start = i;
        while (i < command_text.len and !isSpace(command_text[i]) and !isOperatorStart(command_text, i)) : (i += 1) {}
        if (i > start) {
            try tokens.append(allocator, command_text[start..i]);
        }
    }
    return tokens.toOwnedSlice(allocator);
}

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

/// True when `text[i]` is an unescaped shell operator character (`;`, `|`, `&`).
/// A char preceded by an odd number of backslashes is escaped and not an operator.
fn isOperatorStart(text: []const u8, i: usize) bool {
    const c = text[i];
    if (c != ';' and c != '|' and c != '&') return false;
    return !isEscapedAt(text, i);
}

fn isEscapedAt(text: []const u8, i: usize) bool {
    // Count consecutive backslashes immediately before index i.
    var bs: usize = 0;
    var j = i;
    while (j > 0 and text[j - 1] == '\\') {
        bs += 1;
        j -= 1;
    }
    return (bs % 2) == 1;
}

fn tryEmitOperator(
    allocator: std.mem.Allocator,
    text: []const u8,
    i: *usize,
    tokens: *std.ArrayList([]const u8),
) !bool {
    if (i.* >= text.len) return false;
    if (!isOperatorStart(text, i.*)) return false;
    const c = text[i.*];
    if (c == ';') {
        try tokens.append(allocator, text[i.* .. i.* + 1]);
        i.* += 1;
        return true;
    }
    if (c == '|' or c == '&') {
        // Only treat doubled forms as one operator when the second char is also unescaped
        // (second is adjacent so escape only applies to the first).
        if (i.* + 1 < text.len and text[i.* + 1] == c) {
            try tokens.append(allocator, text[i.* .. i.* + 2]);
            i.* += 2;
            return true;
        }
        try tokens.append(allocator, text[i.* .. i.* + 1]);
        i.* += 1;
        return true;
    }
    return false;
}

/// Curl/wget flags whose following argument is not a transfer URL.
/// `--url` / `-url` are handled separately as transfer-URL sources.
fn curlFlagTakesValue(flag: []const u8) bool {
    // `--name=value` embeds the value; no next-token skip.
    if (std.mem.startsWith(u8, flag, "--") and std.mem.indexOfScalar(u8, flag, '=') != null) return false;
    if (std.mem.eql(u8, flag, "--url") or std.mem.eql(u8, flag, "-url")) return false;

    const value_long = [_][]const u8{
        "--referer",       "--header",               "--user-agent",
        "--cookie",        "--output",               "--user",
        "--proxy",         "--data",                 "--data-raw",
        "--data-binary",   "--data-urlencode",       "--form",
        "--form-string",   "--write-out",            "--cert",
        "--key",           "--cacert",               "--capath",
        "--resolve",       "--connect-to",           "--interface",
        "--dns-servers",   "--config",               "--stderr",
        "--trace",         "--trace-ascii",          "--upload-file",
        "--range",         "--max-time",             "--connect-timeout",
        "--retry",         "--proto",                "--proto-redir",
        "--proto-default", "--proxy-user",           "--oauth2-bearer",
        "--unix-socket",   "--abstract-unix-socket", "--url-query",
        "--json",          "--request",              "--max-redirs",
        "--limit-rate",    "--max-filesize",         "--output-dir",
        "--proxy-header",  "--pinnedpubkey",         "--pass",
        "--engine",        "--ciphers",              "--tls-max",
        "--tls13-ciphers", "--curves",               "--dns-ipv4-addr",
        "--dns-ipv6-addr", "--doh-url",              "--hostpubmd5",
        "--hostpubsha256", "--krb",                  "--login-options",
        "--netrc-file",    "--noproxy",              "--proxy1.0",
        "--pubkey",        "--rate",                 "--sasl-authzid",
        "--tlsuser",       "--tlspassword",          "--aws-sigv4",
        "--hsts",          "--etag-save",            "--etag-compare",
        "--variable",
    };
    for (value_long) |name| {
        if (std.mem.eql(u8, flag, name)) return true;
    }

    // Pure short options that take a value (not combined like -HContent-Type:…).
    if (flag.len == 2 and flag[0] == '-') {
        const c = flag[1];
        return c == 'e' or // --referer
            c == 'H' or // --header
            c == 'A' or // --user-agent
            c == 'b' or // --cookie
            c == 'o' or // --output
            c == 'u' or // --user
            c == 'x' or // --proxy
            c == 'd' or // --data
            c == 'F' or // --form
            c == 'w' or // --write-out
            c == 'K' or // --config
            c == 'T' or // --upload-file
            c == 'r' or // --range
            c == 'm' or // --max-time
            c == 'U' or // --proxy-user
            c == 'X' or // --request
            c == 'E' or // --cert
            c == 'Y' or // --speed-limit
            c == 'y' or // --speed-time
            c == 'C' or // --continue-at
            c == 'z' or // --time-cond
            c == 'c' or // --cookie-jar
            c == 'D' or // --dump-header
            c == 'P'; // --ftp-port
    }
    return false;
}

fn appendUniqueOwnedHost(allocator: std.mem.Allocator, hosts: *std.ArrayList([]const u8), host: []const u8) !void {
    const trimmed = std.mem.trim(u8, host, " \t\r\n");
    if (trimmed.len == 0) return;
    for (hosts.items) |existing| {
        if (std.ascii.eqlIgnoreCase(existing, trimmed)) return;
    }
    const owned = try allocator.dupe(u8, trimmed);
    errdefer allocator.free(owned);
    try hosts.append(allocator, owned);
}

const max_dash_c_depth: u8 = 8;

const CurlDestKind = enum { proxy, connect_to, resolve, doh_url, config };

fn isAllDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn looksLikeInlineUrl(value: []const u8) bool {
    return std.mem.indexOf(u8, value, "://") != null;
}

/// `--proxy`/`-x`, `--connect-to`, `--resolve`, `--doh-url`, `--config`/`-K`
/// (including `--name=value` and attached `-xVALUE` / `-KVALUE`).
fn curlDestKind(flag: []const u8) ?CurlDestKind {
    if (flag.len == 0 or flag[0] != '-') return null;
    if (std.mem.eql(u8, flag, "--proxy") or std.mem.startsWith(u8, flag, "--proxy=")) return .proxy;
    if (std.mem.eql(u8, flag, "--proxy1.0") or std.mem.startsWith(u8, flag, "--proxy1.0=")) return .proxy;
    if (std.mem.eql(u8, flag, "--preproxy") or std.mem.startsWith(u8, flag, "--preproxy=")) return .proxy;
    if (std.mem.eql(u8, flag, "--socks4") or std.mem.startsWith(u8, flag, "--socks4=")) return .proxy;
    if (std.mem.eql(u8, flag, "--socks4a") or std.mem.startsWith(u8, flag, "--socks4a=")) return .proxy;
    if (std.mem.eql(u8, flag, "--socks5") or std.mem.startsWith(u8, flag, "--socks5=")) return .proxy;
    if (std.mem.eql(u8, flag, "--socks5-hostname") or std.mem.startsWith(u8, flag, "--socks5-hostname=")) return .proxy;
    if (std.mem.eql(u8, flag, "-x") or (flag.len > 2 and flag[1] == 'x' and flag[2] != '-')) return .proxy;
    if (std.mem.eql(u8, flag, "--connect-to") or std.mem.startsWith(u8, flag, "--connect-to=")) return .connect_to;
    if (std.mem.eql(u8, flag, "--resolve") or std.mem.startsWith(u8, flag, "--resolve=")) return .resolve;
    if (std.mem.eql(u8, flag, "--doh-url") or std.mem.startsWith(u8, flag, "--doh-url=")) return .doh_url;
    if (std.mem.eql(u8, flag, "--config") or std.mem.startsWith(u8, flag, "--config=")) return .config;
    if (std.mem.eql(u8, flag, "-K") or (flag.len > 2 and flag[1] == 'K')) return .config;
    return null;
}

fn curlDestInlineValue(flag: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, flag, "--")) {
        if (std.mem.indexOfScalar(u8, flag, '=')) |eq| return flag[eq + 1 ..];
        return null;
    }
    if (flag.len > 2) return flag[2..];
    return null;
}

/// CONNECT-TO `HOST:PORT:ADDR:PORT` — dest-check the ADDR hop.
fn destHostFromConnectTo(value: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    const last_colon = std.mem.lastIndexOfScalar(u8, trimmed, ':') orelse
        return network_tags.hostFromUrlOrHost(trimmed);
    if (!isAllDigits(trimmed[last_colon + 1 ..])) return network_tags.hostFromUrlOrHost(trimmed);
    const without_port2 = trimmed[0..last_colon];
    if (without_port2.len >= 2 and without_port2[without_port2.len - 1] == ']') {
        if (std.mem.lastIndexOfScalar(u8, without_port2, '[')) |lb| {
            return without_port2[lb + 1 .. without_port2.len - 1];
        }
    }
    if (std.mem.lastIndexOfScalar(u8, without_port2, ':')) |colon| {
        const addr = without_port2[colon + 1 ..];
        const before = without_port2[0..colon];
        if (std.mem.lastIndexOfScalar(u8, before, ':')) |c2| {
            if (isAllDigits(before[c2 + 1 ..])) return network_tags.hostFromUrlOrHost(addr);
        }
    }
    return network_tags.hostFromUrlOrHost(without_port2);
}

/// `--resolve host:port:addr` — dest-check addr.
fn destHostFromResolve(value: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    var rest = trimmed;
    if (rest.len > 0 and rest[0] == '[') {
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse
            return network_tags.hostFromUrlOrHost(trimmed);
        rest = rest[close + 1 ..];
    } else {
        const colon = std.mem.indexOfScalar(u8, rest, ':') orelse
            return network_tags.hostFromUrlOrHost(trimmed);
        rest = rest[colon..];
    }
    if (rest.len == 0 or rest[0] != ':') return network_tags.hostFromUrlOrHost(trimmed);
    rest = rest[1..];
    const colon = std.mem.indexOfScalar(u8, rest, ':') orelse
        return network_tags.hostFromUrlOrHost(trimmed);
    if (!isAllDigits(rest[0..colon])) return network_tags.hostFromUrlOrHost(trimmed);
    const addr = rest[colon + 1 ..];
    if (addr.len == 0) return network_tags.hostFromUrlOrHost(trimmed);
    return network_tags.hostFromUrlOrHost(addr);
}

fn appendDestFlagHost(
    allocator: std.mem.Allocator,
    hosts: *std.ArrayList([]const u8),
    kind: CurlDestKind,
    value: []const u8,
) !void {
    const host = switch (kind) {
        .proxy, .doh_url => network_tags.hostFromUrlOrHost(value),
        .connect_to => destHostFromConnectTo(value),
        .resolve => destHostFromResolve(value),
        .config => if (looksLikeInlineUrl(value)) network_tags.hostFromUrlOrHost(value) else "",
    };
    if (host.len > 0) try appendUniqueOwnedHost(allocator, hosts, host);
}

fn isDashCShellToken(token: []const u8) bool {
    var base = token;
    if (std.mem.lastIndexOfScalar(u8, token, '/')) |slash| base = token[slash + 1 ..];
    return std.ascii.eqlIgnoreCase(base, "bash") or
        std.ascii.eqlIgnoreCase(base, "sh") or
        std.ascii.eqlIgnoreCase(base, "zsh") or
        std.ascii.eqlIgnoreCase(base, "dash");
}

fn isDashCFlag(token: []const u8) bool {
    if (std.mem.eql(u8, token, "-c") or std.mem.eql(u8, token, "-lc")) return true;
    // Clustered shorts: bash -xc / -ic. Long options are `--…`.
    if (token.len >= 2 and token[0] == '-' and token[1] != '-') {
        for (token[1..]) |ch| {
            if (ch == 'c') return true;
        }
    }
    return false;
}

/// Curl `-K` / `-sK` / `-sKfile` (wget `-K` is `--backup-converted`, not config).
fn curlShortClusterConfigValue(flag: []const u8) ?struct { found: bool, inline_value: ?[]const u8 } {
    if (flag.len < 2 or flag[0] != '-' or flag[1] == '-') return null;
    var i: usize = 1;
    while (i < flag.len) : (i += 1) {
        if (flag[i] == 'K') {
            if (i + 1 < flag.len) return .{ .found = true, .inline_value = flag[i + 1 ..] };
            return .{ .found = true, .inline_value = null };
        }
    }
    return null;
}

fn joinTokenRange(allocator: std.mem.Allocator, tokens: []const []const u8) ![]u8 {
    if (tokens.len == 0) return try allocator.dupe(u8, "");
    if (tokens.len == 1) return try allocator.dupe(u8, tokens[0]);
    var total: usize = tokens.len - 1;
    for (tokens) |t| total += t.len;
    const buf = try allocator.alloc(u8, total);
    var o: usize = 0;
    for (tokens, 0..) |t, i| {
        @memcpy(buf[o..][0..t.len], t);
        o += t.len;
        if (i + 1 < tokens.len) {
            buf[o] = ' ';
            o += 1;
        }
    }
    return buf;
}

fn appendDashCEmbedHosts(
    allocator: std.mem.Allocator,
    tokens: []const []const u8,
    start: usize,
    hosts: *std.ArrayList([]const u8),
    opaque_config: ?*bool,
    depth: u8,
) error{OutOfMemory}!void {
    if (depth >= max_dash_c_depth) return;
    var j = start;
    while (j < tokens.len) : (j += 1) {
        if (isShellOperator(tokens[j])) return;
        const t = tokens[j];
        if (isDashCFlag(t)) {
            const payload_start = j + 1;
            if (payload_start >= tokens.len or isShellOperator(tokens[payload_start])) return;
            var payload_end = payload_start + 1;
            while (payload_end < tokens.len and !isShellOperator(tokens[payload_end])) : (payload_end += 1) {}
            const payload = try joinTokenRange(allocator, tokens[payload_start..payload_end]);
            defer allocator.free(payload);
            try appendCurlLikeHosts(allocator, payload, hosts, opaque_config, depth + 1);
            return;
        }
        if (std.mem.startsWith(u8, t, "-c") and t.len > 2 and t[2] != '-') {
            try appendCurlLikeHosts(allocator, t[2..], hosts, opaque_config, depth + 1);
            return;
        }
        if (t.len > 0 and t[0] == '-') continue;
        return;
    }
}

fn appendCurlOperands(
    allocator: std.mem.Allocator,
    tokens: []const []const u8,
    start: usize,
    hosts: *std.ArrayList([]const u8),
    opaque_config: ?*bool,
    is_curl: bool,
) error{OutOfMemory}!void {
    var j = start;
    while (j < tokens.len) : (j += 1) {
        if (isShellOperator(tokens[j])) break;
        const t = tokens[j];
        if (t.len == 0) continue;

        if (is_curl) {
            if (curlShortClusterConfigValue(t)) |cluster| {
                const value: ?[]const u8 = cluster.inline_value orelse blk: {
                    if (j + 1 < tokens.len and !isShellOperator(tokens[j + 1])) {
                        j += 1;
                        break :blk tokens[j];
                    }
                    break :blk null;
                };
                if (value == null or !looksLikeInlineUrl(value.?)) {
                    if (opaque_config) |p| p.* = true;
                }
                if (value) |v| try appendDestFlagHost(allocator, hosts, .config, v);
                continue;
            }
        }

        if (curlDestKind(t)) |kind| {
            // wget `-K` is `--backup-converted`, not curl `--config`.
            if (kind == .config and !is_curl) continue;
            const value: ?[]const u8 = curlDestInlineValue(t) orelse blk: {
                if (j + 1 < tokens.len and !isShellOperator(tokens[j + 1])) {
                    j += 1;
                    break :blk tokens[j];
                }
                break :blk null;
            };
            if (kind == .config and (value == null or !looksLikeInlineUrl(value.?))) {
                if (opaque_config) |p| p.* = true;
            }
            if (value) |v| try appendDestFlagHost(allocator, hosts, kind, v);
            continue;
        }

        // --url=VALUE / -url=VALUE → transfer URL (always classify).
        if (std.mem.startsWith(u8, t, "--url=") or std.mem.startsWith(u8, t, "-url=")) {
            const raw = if (std.mem.startsWith(u8, t, "--url=")) t["--url=".len..] else t["-url=".len..];
            try appendUniqueOwnedHost(allocator, hosts, network_tags.hostFromUrlOrHost(raw));
            continue;
        }

        // --url / -url VALUE → transfer URL (always classify).
        if ((std.mem.eql(u8, t, "--url") or std.mem.eql(u8, t, "-url")) and j + 1 < tokens.len) {
            try appendUniqueOwnedHost(allocator, hosts, network_tags.hostFromUrlOrHost(tokens[j + 1]));
            j += 1;
            continue;
        }

        // Value-taking options: skip the next token (not a transfer URL).
        if (t[0] == '-') {
            if (curlFlagTakesValue(t) and j + 1 < tokens.len and !isShellOperator(tokens[j + 1])) {
                j += 1; // skip option value
            }
            continue;
        }

        if (startsWithIgnoreCase(t, "https://") or startsWithIgnoreCase(t, "http://")) {
            try appendUniqueOwnedHost(allocator, hosts, network_tags.hostFromUrlOrHost(t));
            continue;
        }

        // Bare host-looking tokens (allowlist default-deny needs unmatched hosts too).
        if (std.mem.indexOfScalar(u8, t, '.') != null) {
            try appendUniqueOwnedHost(allocator, hosts, network_tags.hostFromUrlOrHost(t));
        }
    }
}

/// Collect unique curl/wget transfer + dest-flag hosts from command-position operands.
/// Recurses into `sh`/`bash`/`zsh`/`dash` `-c`/`-lc` payloads. Empty extract is not fail-closed.
fn appendCurlLikeHosts(
    allocator: std.mem.Allocator,
    command_text: []const u8,
    hosts: *std.ArrayList([]const u8),
    opaque_config: ?*bool,
    depth: u8,
) error{OutOfMemory}!void {
    const tokens = try tokenizeSimple(allocator, command_text);
    defer allocator.free(tokens);
    if (tokens.len == 0) return;

    var i: usize = 0;
    while (i < tokens.len) : (i += 1) {
        if (isCurlLikeToken(tokens[i]) and isCommandPosition(tokens, i)) {
            try appendCurlOperands(allocator, tokens, i + 1, hosts, opaque_config, isCurlToken(tokens[i]));
            continue;
        }
        if (isDashCShellToken(tokens[i]) and isCommandPosition(tokens, i)) {
            try appendDashCEmbedHosts(allocator, tokens, i + 1, hosts, opaque_config, depth);
        }
    }
}

/// Append effect hits for every curl/wget URL / tagged host operand in command position.
fn appendCurlLikeHostEffects(
    allocator: std.mem.Allocator,
    command_text: []const u8,
    hits: *std.ArrayList(catalog.EffectHit),
) !void {
    var hosts: std.ArrayList([]const u8) = .empty;
    defer {
        for (hosts.items) |h| allocator.free(h);
        hosts.deinit(allocator);
    }
    try appendCurlLikeHosts(allocator, command_text, &hosts, null, 0);
    for (hosts.items) |host| {
        try appendCurlHostHit(allocator, hits, host);
    }
}

test "open mailto classifies as comms.message" {
    const hits = try classifyCommand(std.testing.allocator, "open 'mailto:x@y.com'");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
    try std.testing.expectEqualStrings("shell_bypass.comms.message.mailto", hits[0].matcher);
}

test "open mailto without quotes" {
    const hits = try classifyCommand(std.testing.allocator, "open mailto:alice@example.com?subject=hi");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expect(std.mem.startsWith(u8, hits[0].matcher, "shell_bypass."));
}

test "open -a Mail mailto still classifies" {
    const hits = try classifyCommand(std.testing.allocator, "open -a Mail mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "open -b bundle mailto still classifies" {
    const hits = try classifyCommand(std.testing.allocator, "open -b com.apple.mail mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "decoy mailto before real open still classifies" {
    const hits = try classifyCommand(std.testing.allocator, "echo mailto:decoy; open mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "incidental open in text is not mailto bypass" {
    const hits = try classifyCommand(std.testing.allocator, "echo 'please open mailto:x@y.com'");
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "printf open mailto args is not mailto bypass" {
    // open/mailto appear as data operands, not as a command launch.
    const hits = try classifyCommand(std.testing.allocator, "printf '%s %s' open mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "sudo open mailto still classifies" {
    const hits = try classifyCommand(std.testing.allocator, "sudo open mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "env assignment before open mailto still classifies" {
    const hits = try classifyCommand(std.testing.allocator, "FOO=1 open mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "unrelated command has no shell bypass hits" {
    const hits = try classifyCommand(std.testing.allocator, "git status");
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "curl to twitter host is publish" {
    const hits = try classifyCommand(std.testing.allocator, "curl -X POST https://api.twitter.com/2/tweets");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
    try std.testing.expect(std.mem.startsWith(u8, hits[0].matcher, "shell_bypass."));
}

test "curl bare tagged host is publish" {
    const hits = try classifyCommand(std.testing.allocator, "curl -X POST api.twitter.com/2/tweets");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "curl multi-URL second tagged host still hits" {
    // First URL is untagged; second is a publish host — must still classify.
    const hits = try classifyCommand(
        std.testing.allocator,
        "curl https://example.com https://api.twitter.com/2/tweets",
    );
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "curl --url tagged host hits" {
    const hits = try classifyCommand(std.testing.allocator, "curl --url https://api.twitter.com/2/tweets");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "curl --url= tagged host hits" {
    const hits = try classifyCommand(std.testing.allocator, "curl --url=https://api.twitter.com/2/tweets");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "curl -url= tagged host hits" {
    const hits = try classifyCommand(std.testing.allocator, "curl -url=https://api.twitter.com/2/tweets");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "sudo -u root curl tagged host is publish" {
    const hits = try classifyCommand(std.testing.allocator, "sudo -u root curl https://api.twitter.com/2/tweets");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "env -i open mailto still classifies" {
    const hits = try classifyCommand(std.testing.allocator, "env -i open mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "sudo -n open -a Mail mailto still classifies" {
    const hits = try classifyCommand(std.testing.allocator, "sudo -n open -a Mail mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "escaped semicolon does not split commands for mailto" {
    // `foo\;` keeps `;` inside the word; open is a printf/arg, not a new command.
    const hits = try classifyCommand(std.testing.allocator, "printf foo\\; open mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "curl --referer tagged host is not publish" {
    const hits = try classifyCommand(
        std.testing.allocator,
        "curl https://example.com --referer https://api.twitter.com/2/tweets",
    );
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "xargs curl tagged host is publish" {
    // Launcher: xargs runs COMMAND; curl must still be command-position.
    const hits = try classifyCommand(
        std.testing.allocator,
        "printf 'arg\\n' | xargs curl https://api.twitter.com/2/tweets",
    );
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "xargs -n 2 curl tagged host is publish" {
    const hits = try classifyCommand(
        std.testing.allocator,
        "xargs -n 2 curl https://api.twitter.com/2/tweets",
    );
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "command -v open mailto is not message bypass" {
    // Bash `command -v` is lookup-only; must not classify as launching open.
    const hits = try classifyCommand(std.testing.allocator, "command -v open mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "command -V open mailto is not message bypass" {
    const hits = try classifyCommand(std.testing.allocator, "command -V open mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "command open mailto still classifies" {
    // `command open` without -v/-V still executes open.
    const hits = try classifyCommand(std.testing.allocator, "command open mailto:x@y.com");
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "curl publish host after more than 48 tokens still classifies" {
    // 25 `-H` pairs push curl+headers+URL past the old 48-token cap so the
    // publish URL was silently dropped and comms.publish never fired.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try list.appendSlice(std.testing.allocator, "curl");
    var i: usize = 0;
    while (i < 25) : (i += 1) {
        var hdr_buf: [32]u8 = undefined;
        const hdr = try std.fmt.bufPrint(&hdr_buf, " -H h{d}:v", .{i});
        try list.appendSlice(std.testing.allocator, hdr);
    }
    try list.appendSlice(std.testing.allocator, " https://api.twitter.com/2/tweets");

    var token_count: usize = 0;
    var it = std.mem.tokenizeAny(u8, list.items, " \t");
    while (it.next()) |_| token_count += 1;
    try std.testing.expect(token_count > 48);

    const hits = try classifyCommand(std.testing.allocator, list.items);
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "extractCurlLikeHosts collects unmatched and allowlisted destinations" {
    const invalid = try extractCurlLikeHosts(std.testing.allocator, "curl https://example.invalid/");
    defer freeCurlLikeHosts(std.testing.allocator, invalid);
    try std.testing.expectEqual(@as(usize, 1), invalid.len);
    try std.testing.expectEqualStrings("example.invalid", invalid[0]);

    const github = try extractCurlLikeHosts(std.testing.allocator, "curl https://api.github.com/");
    defer freeCurlLikeHosts(std.testing.allocator, github);
    try std.testing.expectEqual(@as(usize, 1), github.len);
    try std.testing.expectEqualStrings("api.github.com", github[0]);

    const wget_url = try extractCurlLikeHosts(std.testing.allocator, "wget --url https://example.invalid/install.sh");
    defer freeCurlLikeHosts(std.testing.allocator, wget_url);
    try std.testing.expectEqual(@as(usize, 1), wget_url.len);
    try std.testing.expectEqualStrings("example.invalid", wget_url[0]);
}

fn extractHostsContain(hosts: []const []const u8, want: []const u8) bool {
    for (hosts) |h| {
        if (std.ascii.eqlIgnoreCase(h, want)) return true;
    }
    return false;
}

test "extractCurlLikeHosts unwraps bash -c curl payload" {
    const hosts = try extractCurlLikeHosts(std.testing.allocator, "bash -c 'curl https://example.invalid/'");
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expect(extractHostsContain(hosts, "example.invalid"));
}

test "extractCurlLikeHosts unwraps bash -lc curl payload" {
    const hosts = try extractCurlLikeHosts(std.testing.allocator, "bash -lc 'curl https://example.invalid/'");
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expect(extractHostsContain(hosts, "example.invalid"));
}

test "extractCurlLikeHosts treats --proxy as destination" {
    const hosts = try extractCurlLikeHosts(
        std.testing.allocator,
        "curl -x http://example.invalid https://api.github.com/",
    );
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expect(extractHostsContain(hosts, "example.invalid"));
    try std.testing.expect(extractHostsContain(hosts, "api.github.com"));
}

test "extractCurlLikeHosts treats --connect-to ADDR hop as destination" {
    const hosts = try extractCurlLikeHosts(
        std.testing.allocator,
        "curl --connect-to api.github.com:443:example.invalid:443 https://api.github.com/",
    );
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expect(extractHostsContain(hosts, "example.invalid"));
}

test "extractCurlLikeHosts treats --resolve addr as destination" {
    const hosts = try extractCurlLikeHosts(
        std.testing.allocator,
        "curl --resolve api.github.com:443:example.invalid https://api.github.com/",
    );
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expect(extractHostsContain(hosts, "example.invalid"));
}

test "extractCurlLikeHosts treats --doh-url as destination" {
    const hosts = try extractCurlLikeHosts(
        std.testing.allocator,
        "curl --doh-url https://example.invalid/dns-query https://api.github.com/",
    );
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expect(extractHostsContain(hosts, "example.invalid"));
}

test "extractCurlLikeHosts fail-closes on --config without inline URL" {
    try std.testing.expectError(
        error.UnreadableCurlConfig,
        extractCurlLikeHosts(std.testing.allocator, "curl --config /tmp/curlrc"),
    );
    try std.testing.expectError(
        error.UnreadableCurlConfig,
        extractCurlLikeHosts(std.testing.allocator, "curl -K foo.cfg https://api.github.com/"),
    );
}

test "extractCurlLikeHosts keeps scheme-less localhost empty" {
    const hosts = try extractCurlLikeHosts(std.testing.allocator, "curl localhost");
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expectEqual(@as(usize, 0), hosts.len);
}

test "extractCurlLikeHosts unwraps exec curl" {
    const hosts = try extractCurlLikeHosts(std.testing.allocator, "exec curl https://example.invalid/");
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expect(extractHostsContain(hosts, "example.invalid"));
}

test "extractCurlLikeHosts treats --proxy1.0 and --socks5 as destinations" {
    const proxy = try extractCurlLikeHosts(
        std.testing.allocator,
        "curl --proxy1.0 203.0.113.1:8080 https://api.github.com/",
    );
    defer freeCurlLikeHosts(std.testing.allocator, proxy);
    try std.testing.expect(extractHostsContain(proxy, "203.0.113.1"));
    try std.testing.expect(extractHostsContain(proxy, "api.github.com"));

    const socks = try extractCurlLikeHosts(
        std.testing.allocator,
        "curl --socks5 localhost:1080 https://api.github.com/",
    );
    defer freeCurlLikeHosts(std.testing.allocator, socks);
    try std.testing.expect(extractHostsContain(socks, "localhost"));
    try std.testing.expect(extractHostsContain(socks, "api.github.com"));
}

test "extractCurlLikeHosts unwraps bash -xc curl payload" {
    const hosts = try extractCurlLikeHosts(std.testing.allocator, "bash -xc 'curl https://example.invalid/'");
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expect(extractHostsContain(hosts, "example.invalid"));
}

test "extractCurlLikeHosts fail-closes on curl clustered -sK config" {
    try std.testing.expectError(
        error.UnreadableCurlConfig,
        extractCurlLikeHosts(std.testing.allocator, "curl -sK curlrc https://api.github.com/"),
    );
}

test "extractCurlLikeHosts does not treat wget -K as curl config" {
    const hosts = try extractCurlLikeHosts(std.testing.allocator, "wget -K -q https://example.invalid/");
    defer freeCurlLikeHosts(std.testing.allocator, hosts);
    try std.testing.expect(extractHostsContain(hosts, "example.invalid"));
}
