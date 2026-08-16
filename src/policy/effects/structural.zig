//! Structural (argument key/value) effect classification.
//! Medium-confidence hits from arg shapes; never alone overrides surface deny → allow
//! (enforced by severity merge in evaluate.zig). Deterministic only.

const std = @import("std");
const catalog = @import("catalog.zig");
const ids = @import("ids.zig");
const network_tags = @import("network_tags.zig");

/// Borrowed view of tool-call arguments for classification.
/// Keys and string values must outlive the classify call (typically arena/JSON lifetime).
/// When `string_value_keys` length matches `string_values`, value shapes are gated by key.
pub const ToolArgsView = struct {
    keys: []const []const u8 = &.{},
    string_values: []const []const u8 = &.{},
    /// Parallel to `string_values` when non-empty (same length). Empty = no per-value keys.
    string_value_keys: []const []const u8 = &.{},
};

pub const max_keys: usize = 48;
pub const max_string_values: usize = 16;
pub const max_string_scan_bytes: usize = 4 * 1024;
/// Cap on non-interesting JSON object entries walked (padding fill pass).
pub const max_object_entries_scanned: usize = 256;
/// Hard cap for interesting-key scan (full pass; still bounded to avoid DoS).
pub const max_object_entries_interesting_scan: usize = 4096;

const KeySet = struct {
    /// Required keys (normalized). All must be present.
    keys: []const []const u8,
    effect_id: []const u8,
    matcher: []const u8,
};

/// Required key sets: any one complete set triggers the effect.
const key_sets = [_]KeySet{
    // comms.message
    .{ .keys = &.{ "to", "body" }, .effect_id = "comms.message", .matcher = "structural.comms.message.keys:to+body" },
    .{ .keys = &.{ "to", "message" }, .effect_id = "comms.message", .matcher = "structural.comms.message.keys:to+message" },
    .{ .keys = &.{ "recipient", "body" }, .effect_id = "comms.message", .matcher = "structural.comms.message.keys:recipient+body" },
    .{ .keys = &.{ "recipient", "message" }, .effect_id = "comms.message", .matcher = "structural.comms.message.keys:recipient+message" },
    .{ .keys = &.{ "phone", "text" }, .effect_id = "comms.message", .matcher = "structural.comms.message.keys:phone+text" },
    .{ .keys = &.{ "phone", "message" }, .effect_id = "comms.message", .matcher = "structural.comms.message.keys:phone+message" },
    .{ .keys = &.{ "channel", "text" }, .effect_id = "comms.message", .matcher = "structural.comms.message.keys:channel+text" },
    .{ .keys = &.{ "email", "subject" }, .effect_id = "comms.message", .matcher = "structural.comms.message.keys:email+subject" },
    .{ .keys = &.{ "email", "body" }, .effect_id = "comms.message", .matcher = "structural.comms.message.keys:email+body" },
    // comms.publish — strong publish-specific keys alone (not bare `status`)
    .{ .keys = &.{"tweet"}, .effect_id = "comms.publish", .matcher = "structural.comms.publish.keys:tweet" },
    .{ .keys = &.{"post_text"}, .effect_id = "comms.publish", .matcher = "structural.comms.publish.keys:post_text" },
    // money.transfer
    .{ .keys = &.{ "amount", "currency" }, .effect_id = "money.transfer", .matcher = "structural.money.transfer.keys:amount+currency" },
    .{ .keys = &.{ "amount", "to" }, .effect_id = "money.transfer", .matcher = "structural.money.transfer.keys:amount+to" },
    .{ .keys = &.{ "price", "currency" }, .effect_id = "money.transfer", .matcher = "structural.money.transfer.keys:price+currency" },
    // unknown.external outbound-ish without family
    .{ .keys = &.{ "url", "payload" }, .effect_id = "unknown.external", .matcher = "structural.unknown.external.keys:url+payload" },
};

/// Keys preferred when truncating large arg objects (padding-resistant).
/// Must include every `url_shape_keys` and `contact_keys` member so the interesting-first
/// collection pass cannot drop URL/contact values when other interesting strings fill the cap.
const interesting_keys = [_][]const u8{
    "to",      "body",     "message", "recipient", "phone",    "text",
    "channel", "email",    "subject", "tweet",     "status",   "post_text",
    "amount",  "currency", "price",   "url",       "payload",  "visibility",
    "public",  "from",     "host",    "endpoint",  "base_url", "mailto",
    "href",    "uri",
};

const contact_keys = [_][]const u8{ "to", "email", "recipient", "phone", "from", "mailto" };
const url_shape_keys = [_][]const u8{ "url", "host", "endpoint", "base_url", "href", "uri" };

fn normalizeKey(allocator: std.mem.Allocator, key: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, key.len);
    errdefer allocator.free(out);
    for (key, 0..) |byte, i| {
        const lower = std.ascii.toLower(byte);
        out[i] = if (lower == '-' or lower == '.') '_' else lower;
    }
    return out;
}

fn normalizeKeyBuf(key: []const u8, buf: []u8) ?[]const u8 {
    if (key.len > buf.len) return null;
    for (key, 0..) |byte, i| {
        const lower = std.ascii.toLower(byte);
        buf[i] = if (lower == '-' or lower == '.') '_' else lower;
    }
    return buf[0..key.len];
}

fn hasNormalizedKey(normalized_keys: []const []const u8, required: []const u8) bool {
    for (normalized_keys) |k| {
        if (std.mem.eql(u8, k, required)) return true;
    }
    return false;
}

fn keySetPresent(normalized_keys: []const []const u8, required: []const []const u8) bool {
    for (required) |req| {
        if (!hasNormalizedKey(normalized_keys, req)) return false;
    }
    return true;
}

fn isInterestingKey(normalized: []const u8) bool {
    for (interesting_keys) |k| {
        if (std.mem.eql(u8, normalized, k)) return true;
    }
    return false;
}

fn isContactKey(normalized: []const u8) bool {
    for (contact_keys) |k| {
        if (std.mem.eql(u8, normalized, k)) return true;
    }
    return false;
}

fn isUrlShapeKey(normalized: []const u8) bool {
    for (url_shape_keys) |k| {
        if (std.mem.eql(u8, normalized, k)) return true;
    }
    return false;
}

fn hasContactKey(normalized_keys: []const []const u8) bool {
    for (contact_keys) |k| {
        if (hasNormalizedKey(normalized_keys, k)) return true;
    }
    return false;
}

fn hasUrlShapeKey(normalized_keys: []const []const u8) bool {
    for (url_shape_keys) |k| {
        if (hasNormalizedKey(normalized_keys, k)) return true;
    }
    return false;
}

/// Host file/shell tool focuses — used by structural guards and residual hard-exclude.
pub fn isFileOrShellToolName(tool_name: []const u8) bool {
    const blocked = [_][]const u8{
        "write",     "edit",       "read",              "bash",             "shell",
        "sh",        "zsh",        "exec",              "terminal",         "powershell",
        "pwsh",      "apply",      "create_file",       "file_write",       "file_edit",
        "read_file", "write_file", "run_shell_command", "run_terminal_cmd",
    };
    var buf: [64]u8 = undefined;
    if (tool_name.len > buf.len) return false;
    for (tool_name, 0..) |byte, i| {
        const lower = std.ascii.toLower(byte);
        buf[i] = if (lower == '-' or lower == '.') '_' else lower;
    }
    const n = buf[0..tool_name.len];
    var focus = n;
    if (std.mem.lastIndexOf(u8, n, "__")) |idx| focus = n[idx + 2 ..];
    for (blocked) |b| {
        if (std.mem.eql(u8, focus, b)) return true;
    }
    return false;
}

/// Whole `_`-separated segments only (avoids `postgres_*` matching `post`).
fn hasSegment(normalized: []const u8, token: []const u8) bool {
    var rest = normalized;
    while (rest.len > 0) {
        const sep = std.mem.indexOfScalar(u8, rest, '_');
        const segment = if (sep) |i| rest[0..i] else rest;
        if (std.mem.eql(u8, segment, token)) return true;
        if (sep) |i| {
            rest = rest[i + 1 ..];
        } else break;
    }
    return false;
}

fn nameHasPublishSignal(tool_name: []const u8) bool {
    const tokens = [_][]const u8{ "tweet", "twitter", "post", "publish", "linkedin", "mastodon", "bluesky", "status" };
    var buf: [128]u8 = undefined;
    if (tool_name.len > buf.len) return false;
    for (tool_name, 0..) |byte, i| {
        const lower = std.ascii.toLower(byte);
        buf[i] = if (lower == '-' or lower == '.') '_' else lower;
    }
    const n = buf[0..tool_name.len];
    for (tokens) |t| {
        if (hasSegment(n, t)) return true;
    }
    return false;
}

/// Conservative email: local@domain.tld with simple character classes.
fn looksLikeEmail(value: []const u8) bool {
    if (value.len < 5 or value.len > 254) return false;
    const at = std.mem.indexOfScalar(u8, value, '@') orelse return false;
    if (at == 0 or at + 1 >= value.len) return false;
    const local = value[0..at];
    const domain = value[at + 1 ..];
    if (std.mem.indexOfScalar(u8, domain, '.') == null) return false;
    if (std.mem.indexOfScalar(u8, local, ' ') != null) return false;
    if (std.mem.indexOfScalar(u8, domain, ' ') != null) return false;
    var has_alpha = false;
    for (domain) |c| {
        if (std.ascii.isAlphabetic(c)) has_alpha = true;
        if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '-' or c == '_')) return false;
    }
    return has_alpha;
}

/// E.164-ish: optional +, then 8–15 digits.
fn looksLikePhone(value: []const u8) bool {
    var rest = value;
    if (rest.len > 0 and rest[0] == '+') rest = rest[1..];
    if (rest.len < 8 or rest.len > 15) return false;
    for (rest) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn appendUniquePreferHigher(
    allocator: std.mem.Allocator,
    hits: *std.ArrayList(catalog.EffectHit),
    hit: catalog.EffectHit,
) !void {
    for (hits.items, 0..) |existing, i| {
        if (std.mem.eql(u8, existing.id, hit.id)) {
            if (@intFromEnum(hit.confidence) < @intFromEnum(existing.confidence)) {
                hits.items[i] = hit;
            }
            return;
        }
    }
    try hits.append(allocator, hit);
}

/// Classify tool args into structural effect hits (owned slice).
/// tool_name is used only for false-positive guards and weak publish signals.
pub fn classifyArgs(
    allocator: std.mem.Allocator,
    tool_name: []const u8,
    args: ToolArgsView,
) ![]catalog.EffectHit {
    var hits: std.ArrayList(catalog.EffectHit) = .empty;
    errdefer hits.deinit(allocator);

    var norm_list: std.ArrayList([]const u8) = .empty;
    defer {
        for (norm_list.items) |k| allocator.free(@constCast(k));
        norm_list.deinit(allocator);
    }

    const key_limit = @min(args.keys.len, max_keys);
    for (args.keys[0..key_limit]) |key| {
        const n = try normalizeKey(allocator, key);
        try norm_list.append(allocator, n);
    }
    const normalized_keys = norm_list.items;

    for (key_sets) |set| {
        if (!keySetPresent(normalized_keys, set.keys)) continue;
        try appendUniquePreferHigher(allocator, &hits, .{
            .id = set.effect_id,
            .confidence = .medium,
            .matcher = set.matcher,
        });
    }

    // Bare {status}: only with publish-ish name or visibility/public co-key (not alone).
    const has_status = hasNormalizedKey(normalized_keys, "status");
    const has_visibility = hasNormalizedKey(normalized_keys, "visibility") or hasNormalizedKey(normalized_keys, "public");
    if (has_status and (nameHasPublishSignal(tool_name) or has_visibility)) {
        try appendUniquePreferHigher(allocator, &hits, .{
            .id = "comms.publish",
            .confidence = .medium,
            .matcher = "structural.comms.publish.keys:status",
        });
    }

    // Bare {text} publish: only with publish-ish name or visibility/public, never file/shell tools.
    const has_text = hasNormalizedKey(normalized_keys, "text");
    if (has_text and !isFileOrShellToolName(tool_name)) {
        if (nameHasPublishSignal(tool_name) or has_visibility) {
            try appendUniquePreferHigher(allocator, &hits, .{
                .id = "comms.publish",
                .confidence = .medium,
                .matcher = "structural.comms.publish.keys:text",
            });
        }
    }

    // Value shapes: email/phone require contact-ish keys; hosts require scheme or url-ish keys.
    var scanned: usize = 0;
    const val_limit = @min(args.string_values.len, max_string_values);
    const paired = args.string_value_keys.len == args.string_values.len and args.string_values.len > 0;
    const any_contact = hasContactKey(normalized_keys);
    const any_url_key = hasUrlShapeKey(normalized_keys);

    for (args.string_values[0..val_limit], 0..) |raw, i| {
        if (scanned >= max_string_scan_bytes) break;
        const value = if (raw.len > max_string_scan_bytes - scanned)
            raw[0 .. max_string_scan_bytes - scanned]
        else
            raw;
        scanned += value.len;

        var value_key_norm_buf: [64]u8 = undefined;
        const value_key_norm: ?[]const u8 = if (paired)
            normalizeKeyBuf(args.string_value_keys[i], &value_key_norm_buf)
        else
            null;

        if (looksLikeEmail(value)) {
            const allow = if (value_key_norm) |vk|
                isContactKey(vk)
            else
                any_contact;
            if (allow) {
                try appendUniquePreferHigher(allocator, &hits, .{
                    .id = "comms.message",
                    .confidence = .medium,
                    .matcher = "structural.comms.message.value:email",
                });
            }
        }
        if (looksLikePhone(value)) {
            const allow = if (value_key_norm) |vk|
                isContactKey(vk) or std.mem.eql(u8, vk, "phone")
            else
                any_contact or hasNormalizedKey(normalized_keys, "phone");
            if (allow) {
                try appendUniquePreferHigher(allocator, &hits, .{
                    .id = "comms.message",
                    .confidence = .medium,
                    .matcher = "structural.comms.message.value:phone",
                });
            }
        }

        // URL host tags: require scheme, or url-ish key for this value / object.
        const has_scheme = std.mem.indexOf(u8, value, "://") != null;
        const key_allows_url = if (value_key_norm) |vk| isUrlShapeKey(vk) else any_url_key;
        if (has_scheme or key_allows_url) {
            const host = network_tags.hostFromUrlOrHost(value);
            if (host.len > 0) {
                if (network_tags.effectForHost(host)) |tag| {
                    const matcher: []const u8 = if (std.mem.eql(u8, tag.effect_id, "comms.publish"))
                        "structural.comms.publish.value:url_host"
                    else if (std.mem.eql(u8, tag.effect_id, "comms.message"))
                        "structural.comms.message.value:url_host"
                    else
                        "structural.unknown.external.value:url_host";
                    try appendUniquePreferHigher(allocator, &hits, .{
                        .id = tag.effect_id,
                        .confidence = .medium,
                        .matcher = matcher,
                    });
                }
            }
        }
    }

    for (hits.items) |hit| {
        std.debug.assert(ids.isKnownEffectId(hit.id));
    }
    return try hits.toOwnedSlice(allocator);
}

/// Build a ToolArgsView from a JSON object value (top-level keys + string values).
/// Prefers structurally interesting keys so padding cannot hide `{to,body}`.
/// Flattens one level of nested object keys for membership (bounded).
/// Allocates key/value slices owned by `allocator`.
pub const OwnedArgsView = struct {
    view: ToolArgsView,
    pub fn deinit(self: *OwnedArgsView, allocator: std.mem.Allocator) void {
        for (self.view.keys) |k| allocator.free(@constCast(k));
        if (self.view.keys.len > 0) allocator.free(self.view.keys);
        for (self.view.string_values) |v| allocator.free(@constCast(v));
        if (self.view.string_values.len > 0) allocator.free(self.view.string_values);
        for (self.view.string_value_keys) |k| allocator.free(@constCast(k));
        if (self.view.string_value_keys.len > 0) allocator.free(self.view.string_value_keys);
        self.* = .{ .view = .{} };
    }
};

fn appendKeyIfRoom(
    allocator: std.mem.Allocator,
    keys: *std.ArrayList([]const u8),
    key: []const u8,
    prefer_interesting: bool,
) !void {
    var buf: [128]u8 = undefined;
    const norm = normalizeKeyBuf(key, &buf) orelse return;
    // Dedupe
    for (keys.items) |existing| {
        var ebuf: [128]u8 = undefined;
        const en = normalizeKeyBuf(existing, &ebuf) orelse continue;
        if (std.mem.eql(u8, en, norm)) return;
    }
    if (keys.items.len >= max_keys) {
        if (!prefer_interesting or !isInterestingKey(norm)) return;
        // Try replace a non-interesting key to make room.
        // Allocate first so OOM cannot leave a freed slot for errdefer double-free.
        var replaced = false;
        for (keys.items, 0..) |existing, i| {
            var ebuf: [128]u8 = undefined;
            const en = normalizeKeyBuf(existing, &ebuf) orelse continue;
            if (!isInterestingKey(en)) {
                const new_key = try allocator.dupe(u8, key);
                allocator.free(existing);
                keys.items[i] = new_key;
                replaced = true;
                break;
            }
        }
        if (!replaced) return;
        return;
    }
    try keys.append(allocator, try allocator.dupe(u8, key));
}

fn appendStringValue(
    allocator: std.mem.Allocator,
    strings: *std.ArrayList([]const u8),
    string_keys: *std.ArrayList([]const u8),
    key: []const u8,
    s: []const u8,
    string_bytes: *usize,
    prefer_interesting: bool,
) !void {
    var kbuf: [128]u8 = undefined;
    const knorm = normalizeKeyBuf(key, &kbuf);
    const interesting = if (knorm) |n| isInterestingKey(n) else false;

    if (strings.items.len >= max_string_values) {
        if (!prefer_interesting or !interesting) return;
        // Evict a non-interesting value slot so padding cannot hide email/url shapes.
        // Allocate replacements *before* freeing so OOM cannot leave dangling freed pointers
        // (errdefer on the ArrayList would double-free).
        var replaced = false;
        for (string_keys.items, 0..) |existing_key, i| {
            var ebuf: [128]u8 = undefined;
            const en = normalizeKeyBuf(existing_key, &ebuf) orelse continue;
            if (isInterestingKey(en)) continue;
            const old_len = strings.items[i].len;
            const freed_budget = if (string_bytes.* >= old_len) string_bytes.* - old_len else 0;
            if (freed_budget >= max_string_scan_bytes) continue;
            const take = @min(s.len, max_string_scan_bytes - freed_budget);
            if (take == 0) continue;

            const new_s = try allocator.dupe(u8, s[0..take]);
            errdefer allocator.free(new_s);
            const new_k = try allocator.dupe(u8, key);
            // Ownership transferred into slots; free old after both allocs succeed.
            allocator.free(strings.items[i]);
            allocator.free(string_keys.items[i]);
            strings.items[i] = new_s;
            string_keys.items[i] = new_k;
            string_bytes.* = freed_budget + take;
            replaced = true;
            break;
        }
        if (!replaced) return;
        return;
    }
    if (string_bytes.* >= max_string_scan_bytes) return;
    const take = @min(s.len, max_string_scan_bytes - string_bytes.*);
    // #380: own both slices, reserve list slots, then transfer — no partial-append leak.
    const new_s = try allocator.dupe(u8, s[0..take]);
    errdefer allocator.free(new_s);
    const new_k = try allocator.dupe(u8, key);
    errdefer allocator.free(new_k);
    try strings.ensureUnusedCapacity(allocator, 1);
    try string_keys.ensureUnusedCapacity(allocator, 1);
    strings.appendAssumeCapacity(new_s);
    string_keys.appendAssumeCapacity(new_k);
    string_bytes.* += take;
}

const CollectMode = enum { interesting_only, non_interesting_only };

/// Walk a JSON object collecting keys/values. Two-pass caller uses interesting_only first
/// so late structural fields remain visible after decoy padding (order-independent).
fn collectObjectEntries(
    allocator: std.mem.Allocator,
    object: std.json.ObjectMap,
    keys: *std.ArrayList([]const u8),
    strings: *std.ArrayList([]const u8),
    string_keys: *std.ArrayList([]const u8),
    string_bytes: *usize,
    mode: CollectMode,
) !void {
    const scan_limit: usize = switch (mode) {
        // Interesting pass walks far enough that decoy padding cannot hide to/body.
        .interesting_only => max_object_entries_interesting_scan,
        .non_interesting_only => max_object_entries_scanned,
    };
    var entries_scanned: usize = 0;
    var it = object.iterator();
    while (it.next()) |entry| {
        if (entries_scanned >= scan_limit) break;
        entries_scanned += 1;

        var kbuf: [128]u8 = undefined;
        const knorm = normalizeKeyBuf(entry.key_ptr.*, &kbuf);
        const interesting = if (knorm) |n| isInterestingKey(n) else false;

        // Nested objects: always walk one level for the matching mode (interesting nested
        // keys can hide under a decoy parent key name).
        if (entry.value_ptr.* == .object) {
            try collectNested(
                allocator,
                entry.value_ptr.*.object,
                keys,
                strings,
                string_keys,
                string_bytes,
                mode,
            );
        }

        switch (mode) {
            .interesting_only => if (!interesting) continue,
            .non_interesting_only => if (interesting) continue,
        }

        try appendKeyIfRoom(allocator, keys, entry.key_ptr.*, interesting);

        if (entry.value_ptr.* == .string) {
            try appendStringValue(
                allocator,
                strings,
                string_keys,
                entry.key_ptr.*,
                entry.value_ptr.*.string,
                string_bytes,
                interesting,
            );
        }
    }
}

fn collectNested(
    allocator: std.mem.Allocator,
    nested: std.json.ObjectMap,
    keys: *std.ArrayList([]const u8),
    strings: *std.ArrayList([]const u8),
    string_keys: *std.ArrayList([]const u8),
    string_bytes: *usize,
    mode: CollectMode,
) !void {
    var nit = nested.iterator();
    var nested_scanned: usize = 0;
    while (nit.next()) |nentry| {
        if (nested_scanned >= 64) break;
        nested_scanned += 1;
        var nkbuf: [128]u8 = undefined;
        const nknorm = normalizeKeyBuf(nentry.key_ptr.*, &nkbuf);
        const ninteresting = if (nknorm) |n| isInterestingKey(n) else false;
        switch (mode) {
            .interesting_only => if (!ninteresting) continue,
            .non_interesting_only => if (ninteresting) continue,
        }
        try appendKeyIfRoom(allocator, keys, nentry.key_ptr.*, ninteresting);
        if (nentry.value_ptr.* == .string) {
            try appendStringValue(
                allocator,
                strings,
                string_keys,
                nentry.key_ptr.*,
                nentry.value_ptr.*.string,
                string_bytes,
                ninteresting,
            );
        }
    }
}

pub fn toolArgsViewFromJsonObject(allocator: std.mem.Allocator, value: std.json.Value) !OwnedArgsView {
    if (value != .object) return .{ .view = .{} };

    var keys: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (keys.items) |k| allocator.free(k);
        keys.deinit(allocator);
    }
    var strings: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (strings.items) |s| allocator.free(s);
        strings.deinit(allocator);
    }
    var string_keys: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (string_keys.items) |k| allocator.free(k);
        string_keys.deinit(allocator);
    }

    var string_bytes: usize = 0;

    // Pass 1: interesting keys/values first (padding-resistant regardless of map order).
    try collectObjectEntries(allocator, value.object, &keys, &strings, &string_keys, &string_bytes, .interesting_only);
    // Pass 2: remaining non-interesting entries fill spare capacity (bounded).
    try collectObjectEntries(allocator, value.object, &keys, &strings, &string_keys, &string_bytes, .non_interesting_only);

    return .{
        .view = .{
            .keys = try keys.toOwnedSlice(allocator),
            .string_values = try strings.toOwnedSlice(allocator),
            .string_value_keys = try string_keys.toOwnedSlice(allocator),
        },
    };
}

test "notify with to+body is comms.message structural" {
    const keys = [_][]const u8{ "to", "body" };
    const hits = try classifyArgs(std.testing.allocator, "notify", .{ .keys = &keys });
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
    try std.testing.expect(hits[0].confidence == .medium);
    try std.testing.expect(std.mem.startsWith(u8, hits[0].matcher, "structural."));
}

test "helper with tweet key is comms.publish" {
    const keys = [_][]const u8{"tweet"};
    const hits = try classifyArgs(std.testing.allocator, "helper", .{ .keys = &keys });
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "bare status without publish signal is not publish" {
    const keys = [_][]const u8{"status"};
    const hits = try classifyArgs(std.testing.allocator, "get_job", .{ .keys = &keys });
    defer std.testing.allocator.free(hits);
    for (hits) |h| {
        try std.testing.expect(!std.mem.eql(u8, h.id, "comms.publish"));
    }
}

test "status with publish name is publish" {
    const keys = [_][]const u8{"status"};
    const hits = try classifyArgs(std.testing.allocator, "post_status", .{ .keys = &keys });
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.publish", hits[0].id);
}

test "pay with amount+currency is money.transfer" {
    const keys = [_][]const u8{ "amount", "currency" };
    const hits = try classifyArgs(std.testing.allocator, "pay", .{ .keys = &keys });
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("money.transfer", hits[0].id);
}

test "Write with path content is not comms" {
    const keys = [_][]const u8{ "path", "content" };
    const hits = try classifyArgs(std.testing.allocator, "Write", .{ .keys = &keys });
    defer std.testing.allocator.free(hits);
    for (hits) |h| {
        try std.testing.expect(!std.mem.startsWith(u8, h.id, "comms."));
    }
}

test "Write with bare text key is not publish" {
    const keys = [_][]const u8{"text"};
    const hits = try classifyArgs(std.testing.allocator, "Write", .{ .keys = &keys });
    defer std.testing.allocator.free(hits);
    for (hits) |h| {
        try std.testing.expect(!std.mem.eql(u8, h.id, "comms.publish"));
    }
}

test "postgres tool with text is not publish" {
    const keys = [_][]const u8{"text"};
    const hits = try classifyArgs(std.testing.allocator, "postgres_query", .{ .keys = &keys });
    defer std.testing.allocator.free(hits);
    for (hits) |h| {
        try std.testing.expect(!std.mem.eql(u8, h.id, "comms.publish"));
    }
}

test "empty args yields no structural hits" {
    const hits = try classifyArgs(std.testing.allocator, "notify", .{});
    defer std.testing.allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}

test "email value shape requires contact key" {
    const vals = [_][]const u8{"user@example.com"};
    const vkeys = [_][]const u8{"email"};
    const hits = try classifyArgs(std.testing.allocator, "helper", .{
        .keys = &vkeys,
        .string_values = &vals,
        .string_value_keys = &vkeys,
    });
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
    try std.testing.expect(std.mem.indexOf(u8, hits[0].matcher, "email") != null);
}

test "email value without contact key is not message" {
    const vals = [_][]const u8{"user@example.com"};
    const vkeys = [_][]const u8{"description"};
    const hits = try classifyArgs(std.testing.allocator, "helper", .{
        .keys = &vkeys,
        .string_values = &vals,
        .string_value_keys = &vkeys,
    });
    defer std.testing.allocator.free(hits);
    for (hits) |h| {
        try std.testing.expect(!std.mem.eql(u8, h.id, "comms.message"));
    }
}

test "case and dash insensitive keys" {
    const keys = [_][]const u8{ "To", "Body" };
    const hits = try classifyArgs(std.testing.allocator, "notify", .{ .keys = &keys });
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "json padding cannot hide to+body behind decoy keys" {
    // 40 decoy keys first, then to/body — interesting-key preference must still hit.
    const json =
        \\{"decoy0":"x","decoy1":"x","decoy2":"x","decoy3":"x","decoy4":"x","decoy5":"x","decoy6":"x","decoy7":"x","decoy8":"x","decoy9":"x","decoy10":"x","decoy11":"x","decoy12":"x","decoy13":"x","decoy14":"x","decoy15":"x","decoy16":"x","decoy17":"x","decoy18":"x","decoy19":"x","decoy20":"x","decoy21":"x","decoy22":"x","decoy23":"x","decoy24":"x","decoy25":"x","decoy26":"x","decoy27":"x","decoy28":"x","decoy29":"x","decoy30":"x","decoy31":"x","decoy32":"x","decoy33":"x","decoy34":"x","decoy35":"x","decoy36":"x","decoy37":"x","decoy38":"x","decoy39":"x","to":"a@b.com","body":"hi"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    var owned = try toolArgsViewFromJsonObject(std.testing.allocator, parsed.value);
    defer owned.deinit(std.testing.allocator);
    const hits = try classifyArgs(std.testing.allocator, "notify", owned.view);
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "nested payload to+body is visible" {
    const json =
        \\{"payload":{"to":"a@b.com","body":"hi"}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    var owned = try toolArgsViewFromJsonObject(std.testing.allocator, parsed.value);
    defer owned.deinit(std.testing.allocator);
    const hits = try classifyArgs(std.testing.allocator, "notify", owned.view);
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "string-value padding cannot hide email on contact key" {
    // Fill max_string_values with decoy strings, then place email last.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try list.appendSlice(std.testing.allocator, "{");
    var i: usize = 0;
    while (i < max_string_values) : (i += 1) {
        if (i > 0) try list.appendSlice(std.testing.allocator, ",");
        var decoy_buf: [32]u8 = undefined;
        const decoy = try std.fmt.bufPrint(&decoy_buf, "\"decoy{d}\":\"x\"", .{i});
        try list.appendSlice(std.testing.allocator, decoy);
    }
    try list.appendSlice(std.testing.allocator, ",\"email\":\"user@example.com\"}");
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, list.items, .{});
    defer parsed.deinit();
    var owned = try toolArgsViewFromJsonObject(std.testing.allocator, parsed.value);
    defer owned.deinit(std.testing.allocator);
    const hits = try classifyArgs(std.testing.allocator, "helper", owned.view);
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

test "large decoy object cannot hide to+body past scan window" {
    // More than max_object_entries_scanned decoys, then to/body at the end.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try list.appendSlice(std.testing.allocator, "{");
    var i: usize = 0;
    while (i < max_object_entries_scanned + 8) : (i += 1) {
        if (i > 0) try list.appendSlice(std.testing.allocator, ",");
        var decoy_buf: [32]u8 = undefined;
        const decoy = try std.fmt.bufPrint(&decoy_buf, "\"decoy{d}\":\"x\"", .{i});
        try list.appendSlice(std.testing.allocator, decoy);
    }
    try list.appendSlice(std.testing.allocator, ",\"to\":\"a@b.com\",\"body\":\"hi\"}");
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, list.items, .{});
    defer parsed.deinit();
    var owned = try toolArgsViewFromJsonObject(std.testing.allocator, parsed.value);
    defer owned.deinit(std.testing.allocator);
    const hits = try classifyArgs(std.testing.allocator, "notify", owned.view);
    defer std.testing.allocator.free(hits);
    try std.testing.expect(hits.len >= 1);
    try std.testing.expectEqualStrings("comms.message", hits[0].id);
}

/// Build JSON with a url-shape key first, then enough interesting string fields to fill
/// `max_string_values`. Without that url-shape key in `interesting_keys`, pass 1 fills the
/// cap and pass 2 drops the URL — missing `comms.publish` from the host tag.
fn assertUrlShapeSurvivesInterestingPadding(comptime url_key: []const u8) !void {
    // Exactly max_string_values interesting non-url-shape keys so the budget is full before
    // a non-interesting href/uri would be considered in pass 2.
    const padding_keys = [_][]const u8{
        "to",      "body",     "message", "recipient", "phone",  "text",
        "channel", "email",    "subject", "mailto",    "status", "from",
        "amount",  "currency", "price",   "payload",
    };
    comptime {
        if (padding_keys.len != max_string_values) @compileError("padding must fill max_string_values");
    }

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try list.appendSlice(std.testing.allocator, "{");
    // url-shape key first so, once interesting, it is collected in pass 1 before the cap fills.
    var url_buf: [64]u8 = undefined;
    const url_field = try std.fmt.bufPrint(
        &url_buf,
        "\"{s}\":\"https://api.twitter.com/2/tweets\"",
        .{url_key},
    );
    try list.appendSlice(std.testing.allocator, url_field);
    for (padding_keys) |pk| {
        var pad_buf: [32]u8 = undefined;
        const pad = try std.fmt.bufPrint(&pad_buf, ",\"{s}\":\"x\"", .{pk});
        try list.appendSlice(std.testing.allocator, pad);
    }
    try list.appendSlice(std.testing.allocator, "}");

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, list.items, .{});
    defer parsed.deinit();
    var owned = try toolArgsViewFromJsonObject(std.testing.allocator, parsed.value);
    defer owned.deinit(std.testing.allocator);

    // Ensure the URL string itself survived collection (not merely a key-set publish hit).
    var saw_twitter_url = false;
    for (owned.view.string_values) |v| {
        if (std.mem.indexOf(u8, v, "api.twitter.com") != null) {
            saw_twitter_url = true;
            break;
        }
    }
    try std.testing.expect(saw_twitter_url);

    const hits = try classifyArgs(std.testing.allocator, "helper", owned.view);
    defer std.testing.allocator.free(hits);
    var saw_url_host_publish = false;
    for (hits) |h| {
        if (std.mem.eql(u8, h.id, "comms.publish") and
            std.mem.eql(u8, h.matcher, "structural.comms.publish.value:url_host"))
        {
            saw_url_host_publish = true;
            break;
        }
    }
    try std.testing.expect(saw_url_host_publish);
}

test "href survives max_string_values interesting padding for publish host" {
    try assertUrlShapeSurvivesInterestingPadding("href");
}

test "uri survives max_string_values interesting padding for publish host" {
    try assertUrlShapeSurvivesInterestingPadding("uri");
}

test "url_shape_keys are a subset of interesting_keys" {
    for (url_shape_keys) |uk| {
        try std.testing.expect(isInterestingKey(uk));
    }
    for (contact_keys) |ck| {
        try std.testing.expect(isInterestingKey(ck));
    }
}
