const std = @import("std");

const core = @import("../core/public.zig");
const hash_chain = @import("hash_chain.zig");
const redact_bridge = @import("redact_bridge.zig");
const replay = @import("replay.zig");
const audit_summary = @import("summary.zig");

pub const SessionWriter = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
    audit_dir_name: []const u8 = ".ryk",
    session_id: core.session.SessionId,
    session_dir_path: []u8,
    events_file: std.Io.File,
    previous_hash: ?hash_chain.HashHex = null,
    event_count: usize = 0,
    /// Bytes of events.jsonl this writer has already accounted for. Used to detect
    /// interleaved appends by other writers (shims) cheaply: if the on-disk size
    /// diverges, re-sync the chain tip from disk before the next append (P0-5).
    synced_size: u64 = 0,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, session: core.session.Session) !SessionWriter {
        return initWithDirName(io, allocator, session, ".ryk");
    }

    pub fn initWithDirName(io: std.Io, allocator: std.mem.Allocator, session: core.session.Session, audit_dir_name: []const u8) !SessionWriter {
        if (!safeAuditDirName(audit_dir_name)) return error.InvalidAuditDirName;
        const ryk_dir = try std.fs.path.join(allocator, &.{ session.workspace_root, audit_dir_name });
        defer allocator.free(ryk_dir);
        const sessions_dir = try std.fs.path.join(allocator, &.{ ryk_dir, "sessions" });
        defer allocator.free(sessions_dir);
        const session_dir_path = try std.fs.path.join(allocator, &.{ sessions_dir, session.id.slice() });
        errdefer allocator.free(session_dir_path);

        try std.Io.Dir.cwd().createDirPath(io, session_dir_path);
        const events_path = try std.fs.path.join(allocator, &.{ session_dir_path, "events.jsonl" });
        defer allocator.free(events_path);
        const events_file = try std.Io.Dir.cwd().createFile(io, events_path, .{ .exclusive = true });
        errdefer events_file.close(io);

        return .{
            .io = io,
            .allocator = allocator,
            .workspace_root = session.workspace_root,
            .audit_dir_name = audit_dir_name,
            .session_id = session.id,
            .session_dir_path = session_dir_path,
            .events_file = events_file,
        };
    }

    pub fn openExisting(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, session_id_text: []const u8) !SessionWriter {
        return openExistingWithDirName(io, allocator, workspace_root, session_id_text, ".ryk");
    }

    pub fn openExistingWithDirName(io: std.Io, allocator: std.mem.Allocator, workspace_root: []const u8, session_id_text: []const u8, audit_dir_name: []const u8) !SessionWriter {
        try core.session.validateSessionIdText(session_id_text);
        if (!safeAuditDirName(audit_dir_name)) return error.InvalidAuditDirName;
        const ryk_dir = try std.fs.path.join(allocator, &.{ workspace_root, audit_dir_name });
        defer allocator.free(ryk_dir);
        const sessions_dir = try std.fs.path.join(allocator, &.{ ryk_dir, "sessions" });
        defer allocator.free(sessions_dir);
        const session_dir_path = try std.fs.path.join(allocator, &.{ sessions_dir, session_id_text });
        errdefer allocator.free(session_dir_path);

        const events_path = try std.fs.path.join(allocator, &.{ session_dir_path, "events.jsonl" });
        defer allocator.free(events_path);
        const state = try readExistingState(io, allocator, events_path);

        var events_file = try std.Io.Dir.cwd().openFile(io, events_path, .{ .mode = .read_write });
        errdefer events_file.close(io);
        // Appends are positional (see `appendEvent`), so no global-seek setup is
        // needed here; only record the current size for the resync fast path.
        const end_offset = (try events_file.stat(io)).size;

        var session_id: core.session.SessionId = .{ .value = undefined, .len = 0 };
        if (session_id_text.len > session_id.value.len) return error.InvalidSessionId;
        @memcpy(session_id.value[0..session_id_text.len], session_id_text);
        session_id.len = session_id_text.len;

        return .{
            .io = io,
            .allocator = allocator,
            .workspace_root = workspace_root,
            .audit_dir_name = audit_dir_name,
            .session_id = session_id,
            .session_dir_path = session_dir_path,
            .events_file = events_file,
            .previous_hash = state.previous_hash,
            .event_count = state.event_count,
            .synced_size = end_offset,
        };
    }

    pub fn deinit(self: *SessionWriter) void {
        self.events_file.close(self.io);
        self.allocator.free(self.session_dir_path);
        self.* = undefined;
    }

    pub fn appendEvent(self: *SessionWriter, ev: core.event.Event) !void {
        // P0-5: a long-lived writer must not chain to a stale in-memory tip. Shims
        // append to the same events.jsonl through their own `openExisting` handle,
        // so between two of our appends the on-disk tip may have advanced. Re-sync
        // from disk when the file grew underneath us; otherwise the parent forks
        // the hash chain, making legitimate evidence read as tampered.
        const write_offset = try self.resyncEof();

        var previous: ?[]const u8 = null;
        if (self.previous_hash) |*hash| previous = hash[0..];
        const canonical = try hash_chain.canonicalEventAlloc(self.allocator, ev, previous);
        defer self.allocator.free(canonical);
        const hash = hash_chain.eventHash(previous, canonical);
        const line = try hash_chain.eventJsonLineFromCanonicalAlloc(self.allocator, canonical, &hash);
        defer self.allocator.free(line);

        // Positional append at the true EOF. `writeStreamingAll` targets the OS
        // global seek offset, which a positional `openExisting` seek never moves,
        // so a resumed/shim writer would otherwise clobber existing rows from
        // offset 0. A positional writer pwrites exactly at `write_offset` (P0-5).
        var write_buf: [1024]u8 = undefined;
        var file_writer = self.events_file.writer(self.io, &write_buf);
        try file_writer.seekTo(write_offset);
        try file_writer.interface.writeAll(line);
        try file_writer.interface.flush();
        try self.events_file.sync(self.io);

        self.previous_hash = hash;
        self.event_count += 1;
        self.synced_size = write_offset + line.len;
    }

    /// Return the true end-of-file offset to append at, re-reading chain state
    /// (tip hash + event count) first when the events file grew since our last
    /// append — i.e. another writer (a shim) appended. Fast path is a single
    /// `stat`; the full re-read only runs when interleaving actually happened. A
    /// mid-chain edit still fails `readExistingState`'s strict
    /// `previous_hash == tip` check, so the append fails closed and tamper-evidence
    /// is preserved.
    fn resyncEof(self: *SessionWriter) !u64 {
        const size = (try self.events_file.stat(self.io)).size;
        if (size == self.synced_size) return size;

        const events_path = try std.fs.path.join(self.allocator, &.{ self.session_dir_path, "events.jsonl" });
        defer self.allocator.free(events_path);
        const state = try readExistingState(self.io, self.allocator, events_path);
        self.previous_hash = state.previous_hash;
        self.event_count = state.event_count;
        self.synced_size = size;
        return size;
    }

    pub fn finalHash(self: *const SessionWriter) ?[]const u8 {
        if (self.previous_hash) |*hash| return hash[0..];
        return null;
    }

    pub fn sessionDirPath(self: *const SessionWriter) []const u8 {
        return self.session_dir_path;
    }

    pub fn writeLastPointer(self: *const SessionWriter) !void {
        const ryk_dir = try std.fs.path.join(self.allocator, &.{ self.workspace_root, self.audit_dir_name });
        defer self.allocator.free(ryk_dir);
        try std.Io.Dir.cwd().createDirPath(self.io, ryk_dir);

        const tmp_name = try std.fmt.allocPrint(self.allocator, "last.tmp.{s}", .{self.session_id.slice()});
        defer self.allocator.free(tmp_name);
        const tmp_path = try std.fs.path.join(self.allocator, &.{ ryk_dir, tmp_name });
        defer self.allocator.free(tmp_path);
        const last_path = try std.fs.path.join(self.allocator, &.{ ryk_dir, "last" });
        defer self.allocator.free(last_path);

        {
            const file = try std.Io.Dir.cwd().createFile(self.io, tmp_path, .{});
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, self.session_id.slice());
            try file.writeStreamingAll(self.io, "\n");
            try file.sync(self.io);
        }
        const cwd = std.Io.Dir.cwd();
        try cwd.rename(tmp_path, cwd, last_path, self.io);
    }
};

fn safeAuditDirName(value: []const u8) bool {
    if (value.len == 0 or value.len > 1024 or std.fs.path.isAbsolute(value)) return false;
    if (std.mem.indexOfScalar(u8, value, '\\') != null) return false;
    var parts = std.mem.splitScalar(u8, value, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
        for (part) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    }
    return true;
}

const ExistingState = struct {
    previous_hash: ?hash_chain.HashHex,
    event_count: usize,
};

fn readExistingState(io: std.Io, allocator: std.mem.Allocator, events_path: []const u8) !ExistingState {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, events_path, allocator, .limited(core.limits.max_audit_log_len));
    defer allocator.free(text);
    var previous_hash: ?hash_chain.HashHex = null;
    var event_count: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidEventSchema;
        const object = parsed.value.object;
        const previous_value = object.get("previous_hash") orelse return error.InvalidEventSchema;
        var expected_previous: ?[]const u8 = null;
        if (previous_hash) |*hash| expected_previous = hash[0..];
        if (!jsonNullableStringEquals(previous_value, expected_previous)) return error.InvalidEventSchema;

        const canonical = try replay.canonicalFromJsonValue(allocator, parsed.value);
        defer allocator.free(canonical);
        const computed = hash_chain.eventHash(expected_previous, canonical);
        const hash_value = object.get("event_hash") orelse return error.InvalidEventSchema;
        if (hash_value != .string or !std.mem.eql(u8, hash_value.string, &computed)) return error.InvalidEventSchema;
        var hash: hash_chain.HashHex = undefined;
        @memcpy(hash[0..], &computed);
        previous_hash = hash;
        event_count += 1;
    }
    return .{ .previous_hash = previous_hash, .event_count = event_count };
}

fn jsonNullableStringEquals(value: std.json.Value, expected: ?[]const u8) bool {
    if (expected) |string| return value == .string and std.mem.eql(u8, value.string, string);
    return value == .null;
}

test "session writer creates directory and writes deterministic JSONL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .command = "echo",
        .args = &.{"hello"},
        .workspace_root = root,
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const event_id_text = try std.fmt.bufPrint(&event_id.value, "evt_000001", .{});
    event_id.len = event_id_text.len;
    const ev: core.event.Event = .{
        .session_id = session.id,
        .event_id = event_id,
        .timestamp = ts,
        .event_type = .session_start,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .session, .value = session.id.slice() },
    };

    var session_writer = try SessionWriter.init(std.testing.io, std.testing.allocator, session);
    defer session_writer.deinit();
    try session_writer.appendEvent(ev);

    const rel_events_path = try std.fs.path.join(std.testing.allocator, &.{ ".ryk", "sessions", session.id.slice(), "events.jsonl" });
    defer std.testing.allocator.free(rel_events_path);
    const events = try tmp.dir.readFileAlloc(std.testing.io, rel_events_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(events);

    try std.testing.expect(std.mem.indexOf(u8, events, "\"type\":\"session_start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "\"event_hash\"") != null);
    try std.testing.expectEqual(@as(usize, 1), session_writer.event_count);
}

test "session writer rejects audit directory traversal at the storage boundary" {
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .command = "test",
        .args = &.{},
        .workspace_root = "/tmp/synthetic-workspace",
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };
    try std.testing.expectError(
        error.InvalidAuditDirName,
        SessionWriter.initWithDirName(std.testing.io, std.testing.allocator, session, "../escape"),
    );
    try std.testing.expectError(
        error.InvalidAuditDirName,
        SessionWriter.initWithDirName(std.testing.io, std.testing.allocator, session, ".ryk/../escape"),
    );
}

test "session writer persists redacted synthetic secrets before JSONL write" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .command = "echo",
        .args = &.{"fake_secret_value"},
        .workspace_root = root,
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const event_id_text = try std.fmt.bufPrint(&event_id.value, "evt_000001", .{});
    event_id.len = event_id_text.len;
    const ev: core.event.Event = .{
        .session_id = session.id,
        .event_id = event_id,
        .timestamp = ts,
        .event_type = .process_launch,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "echo fake_secret_value" },
    };

    var session_writer = try SessionWriter.init(std.testing.io, std.testing.allocator, session);
    defer session_writer.deinit();
    try session_writer.appendEvent(ev);

    const rel_events_path = try std.fs.path.join(std.testing.allocator, &.{ ".ryk", "sessions", session.id.slice(), "events.jsonl" });
    defer std.testing.allocator.free(rel_events_path);
    const events = try tmp.dir.readFileAlloc(std.testing.io, rel_events_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(events);

    try std.testing.expect(std.mem.indexOf(u8, events, "fake_secret_value") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, redact_bridge.redacted_value) != null);
}

test "session writer allocation failure leaves a valid complete chain" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .command = "echo",
        .args = &.{"hello"},
        .workspace_root = root,
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    event_id.len = (try std.fmt.bufPrint(&event_id.value, "evt_alloc_fail", .{})).len;
    const ev: core.event.Event = .{
        .session_id = session.id,
        .event_id = event_id,
        .timestamp = ts,
        .event_type = .process_launch,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "token%253Dcorrect-horse-battery-staple" },
    };

    var session_writer = try SessionWriter.init(std.testing.io, std.testing.allocator, session);
    defer session_writer.deinit();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    session_writer.allocator = failing.allocator();
    // Zig 0.16 Writer.Allocating maps allocator exhaustion to WriteFailed.
    try std.testing.expectError(error.WriteFailed, session_writer.appendEvent(ev));
    session_writer.allocator = std.testing.allocator;

    const rel_events_path = try std.fs.path.join(std.testing.allocator, &.{ ".ryk", "sessions", session.id.slice(), "events.jsonl" });
    defer std.testing.allocator.free(rel_events_path);
    const events = try tmp.dir.readFileAlloc(std.testing.io, rel_events_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(events);
    try std.testing.expectEqual(@as(usize, 0), events.len);
    try std.testing.expectEqual(@as(usize, 0), session_writer.event_count);
    try std.testing.expect(session_writer.finalHash() == null);
}

test "session writer redacts embedded secret assignments in command targets" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .command = "/bin/echo",
        .args = &.{"OPENAI_API_KEY=sk-fakeSyntheticOpenAIKey1234567890"},
        .workspace_root = root,
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const event_id_text = try std.fmt.bufPrint(&event_id.value, "evt_000001", .{});
    event_id.len = event_id_text.len;
    const ev: core.event.Event = .{
        .session_id = session.id,
        .event_id = event_id,
        .timestamp = ts,
        .event_type = .process_launch,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "/bin/echo OPENAI_API_KEY=sk-fakeSyntheticOpenAIKey1234567890" },
    };

    var session_writer = try SessionWriter.init(std.testing.io, std.testing.allocator, session);
    defer session_writer.deinit();
    try session_writer.appendEvent(ev);

    const rel_events_path = try std.fs.path.join(std.testing.allocator, &.{ ".ryk", "sessions", session.id.slice(), "events.jsonl" });
    defer std.testing.allocator.free(rel_events_path);
    const events = try tmp.dir.readFileAlloc(std.testing.io, rel_events_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(events);

    try std.testing.expect(std.mem.indexOf(u8, events, "sk-fakeSyntheticOpenAIKey") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, redact_bridge.redacted_value) != null);
}

test "p0-4 write path redacts structured secrets classifyString missed in events.jsonl" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .command = "psql",
        .args = &.{"connect"},
        .workspace_root = root,
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const event_id_text = try std.fmt.bufPrint(&event_id.value, "evt_000001", .{});
    event_id.len = event_id_text.len;
    // Connection-string password (target), JSON password + Authorization header
    // (reason) all bypassed the weak write-time redactor before P0-4.
    const ev: core.event.Event = .{
        .session_id = session.id,
        .event_id = event_id,
        .timestamp = ts,
        .event_type = .command_denied,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .command, .value = "psql mysql://user:pw@dbhost/app" },
        .decision = .{
            .result = .deny,
            .reason = "blocked: {\"password\":\"hunter2\"} Authorization: Bearer abc123def456ghi",
            .ci_may_proceed = false,
        },
    };

    var session_writer = try SessionWriter.init(std.testing.io, std.testing.allocator, session);
    defer session_writer.deinit();
    try session_writer.appendEvent(ev);

    const rel_events_path = try std.fs.path.join(std.testing.allocator, &.{ ".ryk", "sessions", session.id.slice(), "events.jsonl" });
    defer std.testing.allocator.free(rel_events_path);
    const events = try tmp.dir.readFileAlloc(std.testing.io, rel_events_path, std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(events);

    try std.testing.expect(std.mem.indexOf(u8, events, "user:pw") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, "hunter2") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, "abc123def456ghi") == null);
    try std.testing.expect(std.mem.indexOf(u8, events, "[REDACTED") != null);
}

test "openExisting fails closed on tampered existing event chain" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .command = "echo",
        .args = &.{"hello"},
        .workspace_root = root,
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };
    var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    const event_id_text = try std.fmt.bufPrint(&event_id.value, "evt_000001", .{});
    event_id.len = event_id_text.len;
    const ev: core.event.Event = .{
        .session_id = session.id,
        .event_id = event_id,
        .timestamp = ts,
        .event_type = .session_start,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = .session, .value = session.id.slice() },
    };

    {
        var session_writer = try SessionWriter.init(std.testing.io, std.testing.allocator, session);
        defer session_writer.deinit();
        try session_writer.appendEvent(ev);
    }

    const rel_events_path = try std.fs.path.join(std.testing.allocator, &.{ ".ryk", "sessions", session.id.slice(), "events.jsonl" });
    defer std.testing.allocator.free(rel_events_path);
    var events = try tmp.dir.readFileAlloc(std.testing.io, rel_events_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(events);
    const pos = std.mem.indexOf(u8, events, "\"kind\":\"session\"").? + "\"kind\":\"".len;
    @memcpy(events[pos .. pos + "session".len], "command");
    {
        const file = try tmp.dir.createFile(std.testing.io, rel_events_path, .{ .truncate = true });
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, events);
    }

    try std.testing.expectError(error.InvalidEventSchema, SessionWriter.openExisting(std.testing.io, std.testing.allocator, root, session.id.slice()));
}

test "openExisting rejects dot segment session ids before resolving paths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    try std.testing.expectError(error.InvalidSessionId, SessionWriter.openExisting(std.testing.io, std.testing.allocator, root, "."));
    try std.testing.expectError(error.InvalidSessionId, SessionWriter.openExisting(std.testing.io, std.testing.allocator, root, ".."));
}

test "openExisting accepts valid audit logs larger than one MCP message" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .command = "echo",
        .args = &.{"large"},
        .workspace_root = root,
        .mode = .observe,
        .platform = core.platform.detectOs(),
    };

    const large_target = try std.testing.allocator.alloc(u8, core.limits.max_event_field_len - 1024);
    defer std.testing.allocator.free(large_target);
    @memset(large_target, 'x');

    {
        var session_writer = try SessionWriter.init(std.testing.io, std.testing.allocator, session);
        defer session_writer.deinit();

        var index: usize = 0;
        while (index < 18) : (index += 1) {
            var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
            const event_id_text = try std.fmt.bufPrint(&event_id.value, "evt_{d}", .{index});
            event_id.len = event_id_text.len;
            const ev: core.event.Event = .{
                .session_id = session.id,
                .event_id = event_id,
                .timestamp = ts,
                .event_type = .process_launch,
                .actor = .{ .kind = .ryk, .display = "ryk" },
                .target = .{ .kind = .command, .value = large_target },
            };
            try session_writer.appendEvent(ev);
        }
    }

    var resumed = try SessionWriter.openExisting(std.testing.io, std.testing.allocator, root, session.id.slice());
    defer resumed.deinit();
    try std.testing.expectEqual(@as(usize, 18), resumed.event_count);
}

test "session writer preserves interleaved parent and shim appends" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(std.testing.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);
    const ts = core.time.Timestamp.fromUnixSeconds(1_777_983_130);
    const session: core.session.Session = .{
        .id = try core.session.generateSessionId(ts),
        .started_at = ts,
        .command = "ryk",
        .args = &.{"run"},
        .workspace_root = root,
        .mode = .strict,
        .platform = core.platform.detectOs(),
    };

    var parent = try SessionWriter.init(std.testing.io, std.testing.allocator, session);
    defer parent.deinit();
    try parent.appendEvent(try testEvent(session.id, ts, "evt_parent_1", .session_start, .session, session.id.slice()));

    {
        var shim = try SessionWriter.openExisting(std.testing.io, std.testing.allocator, root, session.id.slice());
        defer shim.deinit();
        try shim.appendEvent(try testEvent(session.id, ts, "evt_shim_2", .command_allowed, .command, "git status with a longer shim-side target value"));
    }

    try parent.appendEvent(try testEvent(session.id, ts, "evt_parent_3", .session_exit, .session, session.id.slice()));

    var resumed = try SessionWriter.openExisting(std.testing.io, std.testing.allocator, root, session.id.slice());
    defer resumed.deinit();
    try std.testing.expectEqual(@as(usize, 3), resumed.event_count);

    const rel_events_path = try std.fs.path.join(std.testing.allocator, &.{ ".ryk", "sessions", session.id.slice(), "events.jsonl" });
    defer std.testing.allocator.free(rel_events_path);
    const events = try tmp.dir.readFileAlloc(std.testing.io, rel_events_path, std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(events);
    try std.testing.expect(std.mem.indexOf(u8, events, "evt_shim_2") != null);
    try std.testing.expect(std.mem.indexOf(u8, events, "evt_parent_3") != null);

    // P0-5: the events chain must ALSO satisfy the `ryk replay` verifier
    // (strict `previous_hash == tip`). Before the fix the parent chained its
    // session_exit to a stale tip, so this verification failed even though the
    // evidence was legitimate. Write a matching summary and verify clean.
    var ended = session;
    ended.ended_at = ts;
    const final_hash = resumed.finalHash().?;
    try audit_summary.writeFiles(std.testing.allocator, resumed.session_dir_path, .{
        .session = ended,
        .status = .{ .exited = 0 },
        .event_count = resumed.event_count,
        .final_event_hash = final_hash,
    });

    var clean = try replay.verifySessionDir(std.testing.io, std.testing.allocator, resumed.session_dir_path);
    defer clean.deinit(std.testing.allocator);
    try std.testing.expect(clean.ok);

    // A mid-chain edit must still fail verification (tamper-evidence preserved).
    const tampered = try std.mem.replaceOwned(u8, std.testing.allocator, events, "evt_shim_2", "evt_shim_9");
    defer std.testing.allocator.free(tampered);
    {
        const file = try tmp.dir.createFile(std.testing.io, rel_events_path, .{ .truncate = true });
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, tampered);
    }
    var tamper = try replay.verifySessionDir(std.testing.io, std.testing.allocator, resumed.session_dir_path);
    defer tamper.deinit(std.testing.allocator);
    try std.testing.expect(!tamper.ok);
}

fn testEvent(
    session_id: core.session.SessionId,
    timestamp: core.time.Timestamp,
    event_id_text: []const u8,
    event_type: core.event.EventType,
    target_kind: core.types.TargetKind,
    target_value: []const u8,
) !core.event.Event {
    var event_id: core.event.EventId = .{ .value = undefined, .len = 0 };
    if (event_id_text.len > event_id.value.len) return error.InvalidEventId;
    @memcpy(event_id.value[0..event_id_text.len], event_id_text);
    event_id.len = event_id_text.len;
    return .{
        .session_id = session_id,
        .event_id = event_id,
        .timestamp = timestamp,
        .event_type = event_type,
        .actor = .{ .kind = .ryk, .display = "ryk" },
        .target = .{ .kind = target_kind, .value = target_value },
    };
}
