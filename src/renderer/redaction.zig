const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const oni = @import("oniguruma");
const inputpkg = @import("../input.zig");
const terminal = @import("../terminal/main.zig");
const point = terminal.point;
const Screen = terminal.Screen;
const Terminal = terminal.Terminal;

const log = std.log.scoped(.renderer_redaction);

/// A compiled redaction pattern for the renderer.
pub const Pattern = struct {
    /// The compiled regular expression.
    regex: oni.Regex,

    pub fn deinit(self: *Pattern) void {
        self.regex.deinit();
    }
};

/// A set of redaction patterns. Provides a higher level API for renderers
/// to match against a viewport and determine which cells should be redacted.
pub const Set = struct {
    patterns: []Pattern,

    /// Creates a Set from configuration redaction patterns.
    pub fn fromConfig(
        alloc: Allocator,
        config: []const inputpkg.Redact,
    ) !Set {
        var patterns: std.ArrayList(Pattern) = .empty;
        defer patterns.deinit(alloc);

        for (config) |redact| {
            var regex = redact.oniRegex() catch |err| {
                log.warn("failed to compile redaction regex: {}", .{err});
                continue;
            };
            errdefer regex.deinit();
            try patterns.append(alloc, .{ .regex = regex });
        }

        return .{ .patterns = try patterns.toOwnedSlice(alloc) };
    }

    pub fn deinit(self: *Set, alloc: Allocator) void {
        for (self.patterns) |*pattern| pattern.deinit();
        alloc.free(self.patterns);
    }

    /// Fills the result set with coordinates of cells that should be redacted.
    /// Only cells within capture groups (1+) are marked for redaction.
    pub fn renderCellMap(
        self: *const Set,
        alloc: Allocator,
        result: *terminal.RenderState.CellSet,
        render_state: *const terminal.RenderState,
    ) !void {
        // Fast path if no patterns configured
        if (self.patterns.len == 0) return;

        // Convert render state to a string + byte-to-coordinate map
        var builder: std.Io.Writer.Allocating = .init(alloc);
        defer builder.deinit();
        var map: terminal.RenderState.StringMap = .empty;
        defer map.deinit(alloc);
        try render_state.string(&builder.writer, .{
            .alloc = alloc,
            .map = &map,
        });

        const str = builder.writer.buffered();

        // Process each redaction pattern
        for (self.patterns) |*pattern| {
            var offset: usize = 0;
            while (offset < str.len) {
                var region = pattern.regex.search(
                    str[offset..],
                    .{},
                ) catch |err| switch (err) {
                    error.Mismatch => break,
                    else => return err,
                };
                defer region.deinit();

                const starts = region.starts();
                const ends = region.ends();
                const count = region.count();

                // Get full match end for offset advancement
                const match_end: usize = @intCast(ends[0]);

                // Only process capture groups 1+ (skip group 0 which is full match)
                if (count > 1) {
                    for (1..count) |i| {
                        const group_start: usize = @intCast(starts[i]);
                        const group_end: usize = @intCast(ends[i]);

                        // Skip invalid ranges (group may not participate in match)
                        if (group_start >= group_end) continue;

                        const abs_start = offset + group_start;
                        const abs_end = offset + group_end;

                        // Mark all cells in this capture group for redaction
                        for (map.items[abs_start..abs_end]) |pt| {
                            try result.put(alloc, pt, {});
                        }
                    }
                }

                // Advance past this match
                if (match_end == 0) {
                    offset += 1; // Prevent infinite loop on zero-width match
                } else {
                    offset += match_end;
                }
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "renderCellMap - GitHub token prefix visible" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var t: terminal.Terminal = try .init(alloc, .{
        .cols = 20,
        .rows = 1,
    });
    defer t.deinit(alloc);

    var s = t.vtStream();
    defer s.deinit();
    try s.nextSlice("ghp_abc123secret");

    var state: terminal.RenderState = .empty;
    defer state.deinit(alloc);
    try state.update(alloc, &t);

    // Pattern: ghp_ visible, capture group redacted
    var set = try Set.fromConfig(alloc, &.{
        .{ .regex = "ghp_([A-Za-z0-9]+)" },
    });
    defer set.deinit(alloc);

    var result: terminal.RenderState.CellSet = .empty;
    defer result.deinit(alloc);
    try set.renderCellMap(alloc, &result, &state);

    // "ghp_" (0-3) should NOT be redacted
    try testing.expect(!result.contains(.{ .x = 0, .y = 0 }));
    try testing.expect(!result.contains(.{ .x = 1, .y = 0 }));
    try testing.expect(!result.contains(.{ .x = 2, .y = 0 }));
    try testing.expect(!result.contains(.{ .x = 3, .y = 0 }));

    // "abc123secret" (4-15) SHOULD be redacted
    try testing.expect(result.contains(.{ .x = 4, .y = 0 }));
    try testing.expect(result.contains(.{ .x = 5, .y = 0 }));
    try testing.expect(result.contains(.{ .x = 15, .y = 0 }));
}

test "renderCellMap - Bearer token" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var t: terminal.Terminal = try .init(alloc, .{
        .cols = 30,
        .rows = 1,
    });
    defer t.deinit(alloc);

    var s = t.vtStream();
    defer s.deinit();
    try s.nextSlice("Bearer eyJtoken123");

    var state: terminal.RenderState = .empty;
    defer state.deinit(alloc);
    try state.update(alloc, &t);

    var set = try Set.fromConfig(alloc, &.{
        .{ .regex = "Bearer ([A-Za-z0-9]+)" },
    });
    defer set.deinit(alloc);

    var result: terminal.RenderState.CellSet = .empty;
    defer result.deinit(alloc);
    try set.renderCellMap(alloc, &result, &state);

    // "Bearer " (0-6) should NOT be redacted
    for (0..7) |x| {
        try testing.expect(!result.contains(.{ .x = @intCast(x), .y = 0 }));
    }

    // "eyJtoken123" (7-17) SHOULD be redacted
    try testing.expect(result.contains(.{ .x = 7, .y = 0 }));
    try testing.expect(result.contains(.{ .x = 17, .y = 0 }));
}

test "renderCellMap - no capture groups means no redaction" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var t: terminal.Terminal = try .init(alloc, .{
        .cols = 20,
        .rows = 1,
    });
    defer t.deinit(alloc);

    var s = t.vtStream();
    defer s.deinit();
    try s.nextSlice("ghp_abc123secret");

    var state: terminal.RenderState = .empty;
    defer state.deinit(alloc);
    try state.update(alloc, &t);

    // Pattern WITHOUT capture groups - nothing should be redacted
    var set = try Set.fromConfig(alloc, &.{
        .{ .regex = "ghp_[A-Za-z0-9]+" },
    });
    defer set.deinit(alloc);

    var result: terminal.RenderState.CellSet = .empty;
    defer result.deinit(alloc);
    try set.renderCellMap(alloc, &result, &state);

    // Nothing should be redacted
    for (0..16) |x| {
        try testing.expect(!result.contains(.{ .x = @intCast(x), .y = 0 }));
    }
}

test "renderCellMap - multiple capture groups" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var t: terminal.Terminal = try .init(alloc, .{
        .cols = 30,
        .rows = 1,
    });
    defer t.deinit(alloc);

    var s = t.vtStream();
    defer s.deinit();
    try s.nextSlice("https://user:pass@github.com");

    var state: terminal.RenderState = .empty;
    defer state.deinit(alloc);
    try state.update(alloc, &t);

    // Two capture groups: user and password
    var set = try Set.fromConfig(alloc, &.{
        .{ .regex = "https://([^:]+):([^@]+)@" },
    });
    defer set.deinit(alloc);

    var result: terminal.RenderState.CellSet = .empty;
    defer result.deinit(alloc);
    try set.renderCellMap(alloc, &result, &state);

    // "https://" should NOT be redacted
    for (0..8) |x| {
        try testing.expect(!result.contains(.{ .x = @intCast(x), .y = 0 }));
    }

    // "user" (8-11) SHOULD be redacted
    try testing.expect(result.contains(.{ .x = 8, .y = 0 }));
    try testing.expect(result.contains(.{ .x = 11, .y = 0 }));

    // ":" should NOT be redacted
    try testing.expect(!result.contains(.{ .x = 12, .y = 0 }));

    // "pass" (13-16) SHOULD be redacted
    try testing.expect(result.contains(.{ .x = 13, .y = 0 }));
    try testing.expect(result.contains(.{ .x = 16, .y = 0 }));

    // "@github.com" should NOT be redacted
    try testing.expect(!result.contains(.{ .x = 17, .y = 0 }));
}

test "renderCellMap - URL without credentials not affected" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var t: terminal.Terminal = try .init(alloc, .{
        .cols = 40,
        .rows = 1,
    });
    defer t.deinit(alloc);

    var s = t.vtStream();
    defer s.deinit();
    try s.nextSlice("https://github.com/org/repo");

    var state: terminal.RenderState = .empty;
    defer state.deinit(alloc);
    try state.update(alloc, &t);

    // Pattern for git credentials - should not match plain URLs
    var set = try Set.fromConfig(alloc, &.{
        .{ .regex = "https://([^@]+)@github\\.com" },
    });
    defer set.deinit(alloc);

    var result: terminal.RenderState.CellSet = .empty;
    defer result.deinit(alloc);
    try set.renderCellMap(alloc, &result, &state);

    // Nothing should be redacted - no @ in URL
    for (0..27) |x| {
        try testing.expect(!result.contains(.{ .x = @intCast(x), .y = 0 }));
    }
}

test "renderCellMap - multiple matches in text" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var t: terminal.Terminal = try .init(alloc, .{
        .cols = 40,
        .rows = 1,
    });
    defer t.deinit(alloc);

    var s = t.vtStream();
    defer s.deinit();
    try s.nextSlice("ghp_first ghp_second");

    var state: terminal.RenderState = .empty;
    defer state.deinit(alloc);
    try state.update(alloc, &t);

    var set = try Set.fromConfig(alloc, &.{
        .{ .regex = "ghp_([a-z]+)" },
    });
    defer set.deinit(alloc);

    var result: terminal.RenderState.CellSet = .empty;
    defer result.deinit(alloc);
    try set.renderCellMap(alloc, &result, &state);

    // First "ghp_" NOT redacted
    try testing.expect(!result.contains(.{ .x = 0, .y = 0 }));
    try testing.expect(!result.contains(.{ .x = 3, .y = 0 }));

    // "first" (4-8) SHOULD be redacted
    try testing.expect(result.contains(.{ .x = 4, .y = 0 }));
    try testing.expect(result.contains(.{ .x = 8, .y = 0 }));

    // Space and second "ghp_" NOT redacted
    try testing.expect(!result.contains(.{ .x = 9, .y = 0 }));
    try testing.expect(!result.contains(.{ .x = 10, .y = 0 }));
    try testing.expect(!result.contains(.{ .x = 13, .y = 0 }));

    // "second" (14-19) SHOULD be redacted
    try testing.expect(result.contains(.{ .x = 14, .y = 0 }));
    try testing.expect(result.contains(.{ .x = 19, .y = 0 }));
}

test "renderCellMap - empty patterns" {
    const testing = std.testing;
    const alloc = testing.allocator;

    var t: terminal.Terminal = try .init(alloc, .{
        .cols = 20,
        .rows = 1,
    });
    defer t.deinit(alloc);

    var s = t.vtStream();
    defer s.deinit();
    try s.nextSlice("some text here");

    var state: terminal.RenderState = .empty;
    defer state.deinit(alloc);
    try state.update(alloc, &t);

    var set = try Set.fromConfig(alloc, &.{});
    defer set.deinit(alloc);

    var result: terminal.RenderState.CellSet = .empty;
    defer result.deinit(alloc);
    try set.renderCellMap(alloc, &result, &state);

    // Nothing should be redacted
    try testing.expectEqual(@as(usize, 0), result.count());
}
