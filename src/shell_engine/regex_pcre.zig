//! PCRE2 bindings for shell pack pattern matching.
const std = @import("std");
const c = @cImport({
    @cInclude("pcre2_shim.h");
});

pub const Regex = struct {
    ptr: *c.ryk_regex,

    pub fn compile(pattern: []const u8) !Regex {
        var err_code: c_int = 0;
        var err_off: usize = 0;
        const pattern_ptr: [*]const u8 = if (pattern.len == 0) "".ptr else pattern.ptr;
        const p = c.ryk_regex_compile(pattern_ptr, pattern.len, &err_code, &err_off);
        if (p == null) return error.CompileFailed;
        return .{ .ptr = p.? };
    }

    pub fn deinit(self: *Regex) void {
        c.ryk_regex_free(self.ptr);
        self.* = undefined;
    }

    /// Returns true on match, false on no-match.
    /// Infrastructure / PCRE match errors return `error.MatchInfrastructure` (fail closed).
    pub fn isMatch(self: *const Regex, text: []const u8) !bool {
        return (try self.findMatch(text)) != null;
    }

    pub const MatchSpan = struct {
        start: usize,
        end: usize,
    };

    /// On match, returns the full-match byte span `[start, end)` in `text`.
    /// Infrastructure / PCRE match errors return `error.MatchInfrastructure` (fail closed).
    pub fn findMatch(self: *const Regex, text: []const u8) !?MatchSpan {
        const text_ptr: [*]const u8 = if (text.len == 0) "".ptr else text.ptr;
        var start: usize = 0;
        var end: usize = 0;
        const rc = c.ryk_regex_match_span(self.ptr, text_ptr, text.len, &start, &end);
        if (rc > 0) {
            if (end < start or end > text.len) return error.MatchInfrastructure;
            return .{ .start = start, .end = end };
        }
        if (rc == 0) return null;
        return error.MatchInfrastructure;
    }
};

test "pcre2 matches git reset" {
    var re = try Regex.compile("(?:^|[^[:alnum:]_-])git\\s+(?:\\S+\\s+)*reset\\s+--hard");
    defer re.deinit();
    try std.testing.expect(try re.isMatch("git reset --hard"));
    try std.testing.expect(try re.isMatch("/usr/bin/git reset --hard"));
    try std.testing.expect(try re.isMatch("sudo git reset --hard"));
    try std.testing.expect(!(try re.isMatch("echo hello")));
}

test "pcre2 findMatch returns span for rm -rf flags" {
    var re = try Regex.compile("rm\\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*");
    defer re.deinit();
    const span = (try re.findMatch("rm -rf /tmp")).?;
    try std.testing.expectEqual(@as(usize, 0), span.start);
    try std.testing.expect(span.end >= 5);
    try std.testing.expectEqualStrings("rm -rf", "rm -rf /tmp"[span.start..span.end][0..6]);
}

test "pcre2 unicode property patterns fail closed without UCD" {
    // UNICODE=false: \\p{}/\\P{} must not compile-and-no-match (fail open).
    try std.testing.expectError(error.CompileFailed, Regex.compile("\\p{L}"));
    try std.testing.expectError(error.CompileFailed, Regex.compile("\\P{N}"));
}

test "pcre2 cat-env regex matches head -n 5 .env" {
    var re = try Regex.compile(@embedFile("testdata/cat-env.re"));
    defer re.deinit();
    try std.testing.expect(try re.isMatch("cat .env"));
    try std.testing.expect(try re.isMatch("head -n 5 .env"));
    try std.testing.expect(try re.isMatch("cat -- .env"));
    try std.testing.expect(!(try re.isMatch("head -c 800 /tmp/gw-body-$$.txt")));
}

test "pcre2 no-match is zero and compile errors are not no-match" {
    var re = try Regex.compile("(?:^|[^[:alnum:]_-])git\\s+reset");
    defer re.deinit();
    try std.testing.expect(!(try re.isMatch("echo hello")));
    try std.testing.expectError(error.CompileFailed, Regex.compile("("));
}
