//! Session-scoped in-memory sticky trust store (Phase 2 WP3).
//!
//! After an ask, the host can record once / session / effect-class trust so the
//! next identical fingerprint (or class) skips re-ask. Critical / hard-fence
//! severity can never be sticky-allowed.
//!
//! Lifetime: process/session only — no `.ryk/` persistence (MVP).

const std = @import("std");

/// Sticky grant duration / target.
pub const Scope = enum {
    /// Single-shot: next successful `allows` consumes and clears the entry.
    once,
    /// Persists until `Store.deinit` (session end).
    session,
    /// Trust an effect-class id (pack_id / free-form string).
    effect_class,
};

/// Severity values used to gate `recordFromAsk`. Callers may also pass any
/// enum that has a `.critical` field (e.g. shell_engine.Severity, RiskLevel).
pub const Severity = enum {
    critical,
    high,
    medium,
    low,
    unknown,
};

/// MVP fingerprint: trimmed command string. Optional `rule_id` is reserved for
/// a later composite key; ignored for now so callers can pass it without churn.
pub fn fingerprintCommand(cmd: []const u8, rule_id: ?[]const u8) []const u8 {
    _ = rule_id;
    return normalize(cmd);
}

fn normalize(raw: []const u8) []const u8 {
    return std.mem.trim(u8, raw, " \t\r\n");
}

fn isCritical(severity: anytype) bool {
    return severity == .critical;
}

/// Cap sticky maps so long-lived hosts cannot grow unbounded (M013).
/// once shrinks on consume; session/effect_classes only grow without a cap.
pub const max_sticky_entries: usize = 4096;

/// In-memory sticky trust map for one agent/hook session.
pub const Store = struct {
    allocator: std.mem.Allocator,
    once: std.StringHashMap(void),
    session: std.StringHashMap(void),
    effect_classes: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator) Store {
        return .{
            .allocator = allocator,
            .once = std.StringHashMap(void).init(allocator),
            .session = std.StringHashMap(void).init(allocator),
            .effect_classes = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        freeOwnedKeys(&self.once, self.allocator);
        freeOwnedKeys(&self.session, self.allocator);
        freeOwnedKeys(&self.effect_classes, self.allocator);
        self.* = undefined;
    }

    /// True if fingerprint has session trust or a consumable once grant.
    ///
    /// **Once consume:** a once grant is removed **only when this returns true**.
    /// Callers that may still deny after a lookup (e.g. hard fence) must not call
    /// `allows` until the allow decision is committed — see `decideShellWithPolicy`,
    /// which checks critical / fail-closed / CI **before** calling `allows`.
    pub fn allows(self: *Store, fingerprint: []const u8) bool {
        const fp = normalize(fingerprint);
        if (self.once.getKey(fp)) |owned_key| {
            _ = self.once.remove(fp);
            self.allocator.free(owned_key);
            return true;
        }
        return self.session.contains(fp);
    }

    /// Non-consuming once-grant probe (does not free). Prefer for preflight checks
    /// when the caller might still deny; use `allows` only when allow is committed.
    pub fn hasOnce(self: *const Store, fingerprint: []const u8) bool {
        return self.once.contains(normalize(fingerprint));
    }

    pub fn allowsEffectClass(self: *const Store, class_id: []const u8) bool {
        return self.effect_classes.contains(normalize(class_id));
    }

    pub fn recordAllowOnce(self: *Store, fingerprint: []const u8) !void {
        try putOwnedKey(&self.once, self.allocator, fingerprint);
    }

    pub fn recordAllowSession(self: *Store, fingerprint: []const u8) !void {
        try putOwnedKey(&self.session, self.allocator, fingerprint);
    }

    pub fn recordAllowEffectClass(self: *Store, class_id: []const u8) !void {
        try putOwnedKey(&self.effect_classes, self.allocator, class_id);
    }

    /// Record sticky trust after a user allow-from-ask.
    /// **No-op** when `severity` is `.critical` — hard fence is never sticky.
    /// For `.effect_class`, `fingerprint` is treated as the class id.
    pub fn recordFromAsk(
        self: *Store,
        fingerprint: []const u8,
        scope: Scope,
        severity: anytype,
    ) !void {
        if (isCritical(severity)) return;
        switch (scope) {
            .once => try self.recordAllowOnce(fingerprint),
            .session => try self.recordAllowSession(fingerprint),
            .effect_class => try self.recordAllowEffectClass(fingerprint),
        }
    }
};

fn freeOwnedKeys(map: *std.StringHashMap(void), allocator: std.mem.Allocator) void {
    var it = map.keyIterator();
    while (it.next()) |key| {
        allocator.free(key.*);
    }
    map.deinit();
}

fn putOwnedKey(map: *std.StringHashMap(void), allocator: std.mem.Allocator, raw: []const u8) !void {
    const normalized = normalize(raw);
    if (map.contains(normalized)) return;
    // Cap: skip insert when full so long sessions re-ask instead of growing forever (M013).
    // Soft miss is safer than erroring the whole allow path mid-ask.
    if (map.count() >= max_sticky_entries) return;
    const owned = try allocator.dupe(u8, normalized);
    errdefer allocator.free(owned);
    try map.put(owned, {});
}

// ─── tests (TDD seams: Store public API) ───────────────────────────────────

test "sticky allowOnce consumes on next allows" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator);
    defer store.deinit();

    const fp = fingerprintCommand("  npm test  ", null);
    try std.testing.expect(!store.allows(fp));

    try store.recordAllowOnce(fp);
    try std.testing.expect(store.allows("npm test")); // trim-normalized match + consume
    try std.testing.expect(!store.allows("npm test")); // gone after one hit
}

test "sticky allowSession persists until deinit" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator);
    defer store.deinit();

    try store.recordAllowSession("git status");
    try std.testing.expect(store.allows("git status"));
    try std.testing.expect(store.allows("  git status  "));
    try std.testing.expect(store.allows("git status")); // still sticky
    try std.testing.expect(!store.allows("npm test"));
}

test "sticky allowEffectClass hits by class id" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator);
    defer store.deinit();

    try std.testing.expect(!store.allowsEffectClass("core.git"));
    try store.recordAllowEffectClass("  core.git  ");
    try std.testing.expect(store.allowsEffectClass("core.git"));
    try std.testing.expect(store.allowsEffectClass(" core.git "));
    try std.testing.expect(!store.allowsEffectClass("core.filesystem"));
    // effect-class does not imply command fingerprint trust
    try std.testing.expect(!store.allows("git push --force"));
}

test "sticky recordFromAsk cannot sticky critical" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator);
    defer store.deinit();

    const fp = "rm -rf /";
    // critical → no-op for every scope
    try store.recordFromAsk(fp, .once, Severity.critical);
    try store.recordFromAsk(fp, .session, Severity.critical);
    try store.recordFromAsk("core.filesystem", .effect_class, Severity.critical);

    try std.testing.expect(!store.allows(fp));
    try std.testing.expect(!store.allowsEffectClass("core.filesystem"));

    // non-critical may record
    try store.recordFromAsk("npm test", .session, Severity.high);
    try std.testing.expect(store.allows("npm test"));

    try store.recordFromAsk("cargo test", .once, Severity.medium);
    try std.testing.expect(store.allows("cargo test"));
    try std.testing.expect(!store.allows("cargo test"));

    try store.recordFromAsk("core.network", .effect_class, Severity.low);
    try std.testing.expect(store.allowsEffectClass("core.network"));
}

test "sticky recordFromAsk accepts foreign critical tags" {
    // WP4 will pass shell RiskLevel / shell_engine.Severity — gate by tag only.
    const Foreign = enum { low, high, critical };
    const allocator = std.testing.allocator;
    var store = Store.init(allocator);
    defer store.deinit();

    try store.recordFromAsk("dd if=/dev/zero of=/dev/sda", .session, Foreign.critical);
    try std.testing.expect(!store.allows("dd if=/dev/zero of=/dev/sda"));

    try store.recordFromAsk("echo ok", .session, Foreign.high);
    try std.testing.expect(store.allows("echo ok"));
}

test "sticky fingerprintCommand trims and ignores rule_id for MVP" {
    const a = fingerprintCommand("  ls -la  ", "rule-1");
    const b = fingerprintCommand("ls -la", null);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expectEqualStrings("ls -la", a);
}

test "sticky hasOnce peeks without consuming once grant" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator);
    defer store.deinit();

    try store.recordAllowOnce("npm install bad");
    try std.testing.expect(store.hasOnce("npm install bad"));
    try std.testing.expect(store.hasOnce("  npm install bad  "));
    // Peek must not consume.
    try std.testing.expect(store.hasOnce("npm install bad"));
    try std.testing.expect(store.allows("npm install bad")); // consume
    try std.testing.expect(!store.hasOnce("npm install bad"));
    try std.testing.expect(!store.allows("npm install bad"));
}

test "sticky session map soft-caps at max_sticky_entries" {
    const allocator = std.testing.allocator;
    var store = Store.init(allocator);
    defer store.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < max_sticky_entries) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "cmd-{d}", .{i});
        try store.recordAllowSession(key);
    }
    try std.testing.expectEqual(@as(usize, max_sticky_entries), store.session.count());

    // Cap full: insert is a soft no-op (re-ask), not unbounded growth or hard error.
    try store.recordAllowSession("overflow-key");
    try std.testing.expectEqual(@as(usize, max_sticky_entries), store.session.count());
    try std.testing.expect(!store.allows("overflow-key"));
    try std.testing.expect(store.allows("cmd-0"));
}
