const std = @import("std");

pub const VarClass = enum {
    public,
    sensitive,

    fn parse(value: []const u8) ?VarClass {
        if (std.mem.eql(u8, value, "public")) return .public;
        if (std.mem.eql(u8, value, "sensitive")) return .sensitive;
        return null;
    }
};

pub const Variable = struct {
    name: []u8,
    class: VarClass,
    grant: ?[]u8 = null,

    fn deinit(self: Variable, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.grant) |grant| allocator.free(grant);
    }
};

pub const Schema = struct {
    allocator: std.mem.Allocator,
    vars: []Variable,

    pub fn deinit(self: *Schema) void {
        for (self.vars) |variable| variable.deinit(self.allocator);
        self.allocator.free(self.vars);
        self.* = undefined;
    }

    pub fn find(self: *const Schema, name: []const u8) ?*const Variable {
        for (self.vars) |*variable| {
            if (std.mem.eql(u8, variable.name, name)) return variable;
        }
        return null;
    }
};

const Builder = struct {
    name: []u8,
    class: ?VarClass = null,
    grant: ?[]u8 = null,
    // Once true, name/grant belong to a Variable (or were already freed).
    // Never poison the slices: a second deinit must be a no-op, not a GPF.
    taken: bool = false,

    fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        if (self.taken) return;
        self.taken = true;
        allocator.free(self.name);
        if (self.grant) |grant| allocator.free(grant);
    }

    fn intoVariable(self: *Builder) !Variable {
        const class = self.class orelse return error.InvalidEnvSchema;
        if (class == .public and self.grant != null) return error.InvalidEnvSchema;
        const variable: Variable = .{ .name = self.name, .class = class, .grant = self.grant };
        self.taken = true;
        return variable;
    }
};

pub fn parseFromSlice(allocator: std.mem.Allocator, text: []const u8) !Schema {
    var variables: std.ArrayList(Variable) = .empty;
    errdefer {
        for (variables.items) |variable| variable.deinit(allocator);
        variables.deinit(allocator);
    }
    // Explicit flag — do not store Builder in an optional. Copying `?Builder`
    // and then nulling the optional left a second slice header; Linux
    // checkAllAllocationFailures then GPF'd in Allocator.free.
    var has_active = false;
    var active: Builder = undefined;
    defer if (has_active) {
        has_active = false;
        active.deinit(allocator);
    };
    var saw_unknown_omit = false;
    var section: enum { none, defaults, vars } = .none;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const without_cr = std.mem.trimEnd(u8, raw_line, "\r");
        const content = std.mem.trim(u8, without_cr, " ");
        if (content.len == 0 or content[0] == '#') continue;
        if (std.mem.indexOfScalar(u8, without_cr, '\t') != null) return error.InvalidEnvSchema;
        const indent = without_cr.len - std.mem.trimStart(u8, without_cr, " ").len;

        if (indent == 0 and std.mem.eql(u8, content, "defaults:")) {
            try finishActive(allocator, &variables, &has_active, &active);
            section = .defaults;
            continue;
        }
        if (indent == 0 and std.mem.eql(u8, content, "vars:")) {
            try finishActive(allocator, &variables, &has_active, &active);
            section = .vars;
            continue;
        }
        if (section == .defaults and indent == 2) {
            const pair = try splitPair(content);
            if (!std.mem.eql(u8, pair.key, "unknown") or !std.mem.eql(u8, pair.value, "omit")) {
                return error.InvalidEnvSchema;
            }
            if (saw_unknown_omit) return error.InvalidEnvSchema;
            saw_unknown_omit = true;
            continue;
        }
        if (section == .vars and indent == 2 and std.mem.endsWith(u8, content, ":")) {
            try finishActive(allocator, &variables, &has_active, &active);
            const name = std.mem.trim(u8, content[0 .. content.len - 1], " ");
            try validateEnvName(name);
            for (variables.items) |variable| {
                if (std.mem.eql(u8, variable.name, name)) return error.InvalidEnvSchema;
            }
            active = .{ .name = try allocator.dupe(u8, name) };
            has_active = true;
            continue;
        }
        if (section == .vars and indent == 4) {
            if (!has_active) return error.InvalidEnvSchema;
            const pair = try splitPair(content);
            if (std.mem.eql(u8, pair.key, "class")) {
                if (active.class != null) return error.InvalidEnvSchema;
                active.class = VarClass.parse(pair.value) orelse return error.InvalidEnvSchema;
            } else if (std.mem.eql(u8, pair.key, "grant")) {
                if (active.grant != null or pair.value.len == 0) return error.InvalidEnvSchema;
                active.grant = try allocator.dupe(u8, pair.value);
            } else return error.InvalidEnvSchema;
            continue;
        }
        return error.InvalidEnvSchema;
    }
    try finishActive(allocator, &variables, &has_active, &active);
    if (!saw_unknown_omit) return error.InvalidEnvSchema;
    return .{ .allocator = allocator, .vars = try variables.toOwnedSlice(allocator) };
}

pub fn loadOptional(
    io: std.Io,
    allocator: std.mem.Allocator,
    workspace_root: []const u8,
) !?Schema {
    const path = try std.fs.path.join(allocator, &.{ workspace_root, ".ryk", "env.schema.yaml" });
    defer allocator.free(path);
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(text);
    return try parseFromSlice(allocator, text);
}

fn finishActive(
    allocator: std.mem.Allocator,
    variables: *std.ArrayList(Variable),
    has_active: *bool,
    active: *Builder,
) !void {
    if (!has_active.*) return;
    has_active.* = false;
    var transferred = false;
    defer if (!transferred) active.deinit(allocator);
    const variable = try active.intoVariable();
    transferred = true;
    errdefer variable.deinit(allocator);
    try variables.append(allocator, variable);
}

const Pair = struct { key: []const u8, value: []const u8 };
fn splitPair(content: []const u8) !Pair {
    const colon = std.mem.indexOfScalar(u8, content, ':') orelse return error.InvalidEnvSchema;
    const key = std.mem.trim(u8, content[0..colon], " ");
    const value = std.mem.trim(u8, content[colon + 1 ..], " ");
    if (key.len == 0 or value.len == 0 or std.mem.indexOfScalar(u8, value, ':') != null) {
        return error.InvalidEnvSchema;
    }
    return .{ .key = key, .value = value };
}

fn validateEnvName(name: []const u8) !void {
    if (name.len == 0 or !(std.ascii.isAlphabetic(name[0]) or name[0] == '_')) {
        return error.InvalidEnvSchema;
    }
    for (name[1..]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '_')) return error.InvalidEnvSchema;
    }
}

test "env schema parses public and sensitive variables and rejects malformed contracts" {
    var schema = try parseFromSlice(std.testing.allocator,
        \\defaults:
        \\  unknown: omit
        \\vars:
        \\  API_URL:
        \\    class: public
        \\  DATABASE_URL:
        \\    class: sensitive
        \\    grant: database
    );
    defer schema.deinit();
    try std.testing.expectEqual(VarClass.public, schema.find("API_URL").?.class);
    try std.testing.expectEqualStrings("database", schema.find("DATABASE_URL").?.grant.?);
    try std.testing.expect(schema.find("UNKNOWN") == null);
    try std.testing.expectError(error.InvalidEnvSchema, parseFromSlice(std.testing.allocator,
        \\defaults:
        \\  unknown: inherit
        \\vars:
        \\  BAD-NAME:
        \\    class: public
    ));
}

test "env schema parser cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseAllocationProbe, .{});
}

fn parseAllocationProbe(allocator: std.mem.Allocator) !void {
    var schema = try parseFromSlice(allocator,
        \\defaults:
        \\  unknown: omit
        \\vars:
        \\  API_URL:
        \\    class: public
        \\  DATABASE_URL:
        \\    class: sensitive
        \\    grant: database
    );
    defer schema.deinit();
}
