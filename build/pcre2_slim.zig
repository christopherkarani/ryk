//! Documented fork of PCRE2 10.48 `build.zig` (`@5a632d3`).
//!
//! Upstream hardcodes `SUPPORT_UNICODE = true` and always compiles UCD, DFA,
//! substitute, convert, serialize, and UTF helpers. ryk's shim only
//! compile / match / span (byte patterns, UTF off, JIT already default false).
//! This builder keeps the same tarball pin and emits a static `pcre2-8` with
//! those tables and APIs dropped. See `docs/dev/pcre2-slim.md`.

const std = @import("std");

pub const SlimPcre2 = struct {
    lib: *std.Build.Step.Compile,
    include_dir: std.Build.LazyPath,
};

pub fn addLibrary(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) SlimPcre2 {
    // Fetch the pinned tarball only. Do not link upstream's artifact — that
    // build has no flag to drop UNICODE/UCD/DFA/substitute.
    const pcre2_dep = b.dependency("pcre2", .{
        .target = target,
        .optimize = optimize,
        .linkage = .static,
    });

    const rt = target.result;
    const is_unix = rt.os.tag != .windows;
    const is_mingw = rt.isMinGW();
    const is_musl = rt.isMuslLibC();
    const is_glibc = rt.isGnuLibC();
    const is_freebsd = rt.isFreeBSDLibC();

    const pcre2_h_dir = b.addWriteFiles();
    const pcre2_h = pcre2_h_dir.addCopyFile(pcre2_dep.path("src/pcre2.h.generic"), "pcre2.h");

    const config_h = b.addConfigHeader(.{
        .style = .{ .cmake = pcre2_dep.path("src/config-cmake.h.in") },
        .include_path = "config.h",
    }, .{
        .HAVE_ASSERT_H = true,
        .HAVE_DIRENT_H = is_unix or is_mingw,
        .HAVE_SYS_STAT_H = true,
        .HAVE_SYS_TYPES_H = true,
        .HAVE_UNISTD_H = is_unix or is_mingw,
        .HAVE_WINDOWS_H = rt.os.tag == .windows,
        .HAVE_MEMFD_CREATE = is_musl or is_glibc or is_freebsd,
        .HAVE_SECURE_GETENV = is_musl or is_glibc or is_freebsd,
        .HAVE_SETRLIMIT = is_unix and !is_mingw,
        .HAVE_BUILTIN_ASSUME = null,
        .HAVE_BUILTIN_MUL_OVERFLOW = true,
        .HAVE_BUILTIN_UNREACHABLE = true,
        .HAVE_ATTRIBUTE_UNINITIALIZED = true,
        .SUPPORT_PCRE2_8 = true,
        .SUPPORT_PCRE2_16 = false,
        .SUPPORT_PCRE2_32 = false,
        // The size win. Dummy UCD objects remain so omitted Unicode .c files
        // are not referenced; the 116 KiB property tables are not compiled.
        .SUPPORT_UNICODE = false,
        .SUPPORT_JIT = false,
        .PCRE2_EXPORT = "__attribute__ ((visibility (\"default\")))",
        .PCRE2_LINK_SIZE = 2,
        .PCRE2_PARENS_NEST_LIMIT = 250,
        .PCRE2_HEAP_LIMIT = 20000000,
        .PCRE2_MAX_VARLOOKBEHIND = 255,
        .PCRE2_MATCH_LIMIT = 10000000,
        .PCRE2_MATCH_LIMIT_DEPTH = "MATCH_LIMIT",
        .PCRE2GREP_BUFSIZE = 20480,
        .PCRE2GREP_MAX_BUFSIZE = 1048576,
        .NEWLINE_DEFAULT = 2,
    });

    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lib_mod.addCMacro("HAVE_CONFIG_H", "");
    lib_mod.addCMacro("PCRE2_CODE_UNIT_WIDTH", "8");
    lib_mod.addCMacro("PCRE2_STATIC", "");
    lib_mod.addConfigHeader(config_h);
    lib_mod.addIncludePath(pcre2_h_dir.getDirectory());
    lib_mod.addIncludePath(pcre2_dep.path("src"));

    const cflags = &.{"-fvisibility=hidden"};
    lib_mod.addCSourceFile(.{
        .file = b.addWriteFiles().addCopyFile(
            pcre2_dep.path("src/pcre2_chartables.c.dist"),
            "pcre2_chartables.c",
        ),
        .flags = cflags,
    });
    // Match + compile only. Upstream also ships DFA, substitute, convert,
    // serialize, and UTF/UCP helpers; ryk never calls those APIs.
    lib_mod.addCSourceFiles(.{
        .root = pcre2_dep.path("src"),
        .files = &.{
            "pcre2_auto_possess.c",
            "pcre2_chkdint.c",
            "pcre2_compile.c",
            "pcre2_compile_cgroup.c",
            "pcre2_compile_class.c",
            "pcre2_config.c",
            "pcre2_context.c",
            "pcre2_error.c",
            "pcre2_find_bracket.c",
            "pcre2_jit_compile.c",
            "pcre2_maketables.c",
            "pcre2_match.c",
            "pcre2_match_data.c",
            "pcre2_match_next.c",
            "pcre2_newline.c",
            "pcre2_pattern_info.c",
            "pcre2_script_run.c",
            "pcre2_string_utils.c",
            "pcre2_study.c",
            "pcre2_substring.c",
            "pcre2_tables.c",
            "pcre2_ucd.c",
            "pcre2_valid_utf.c",
            "pcre2_xclass.c",
        },
        .flags = cflags,
    });

    const lib = b.addLibrary(.{
        .name = "pcre2-8",
        .root_module = lib_mod,
        .linkage = .static,
    });
    lib.installHeader(pcre2_h, "pcre2.h");

    return .{
        .lib = lib,
        .include_dir = pcre2_h_dir.getDirectory(),
    };
}
