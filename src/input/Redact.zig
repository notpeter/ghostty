//! A redaction pattern that matches sensitive text and identifies capture
//! groups to be visually redacted. Only capture groups are redacted; the
//! non-captured portions of the match remain visible.
const Redact = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const oni = @import("oniguruma");

/// The regular expression pattern. Ownership of this memory is up to the
/// caller. The Redact struct will never free this memory.
regex: []const u8,

/// Returns a compiled Oniguruma regex for this pattern.
pub fn oniRegex(self: *const Redact) !oni.Regex {
    return try oni.Regex.init(
        self.regex,
        .{},
        oni.Encoding.utf8,
        oni.Syntax.default,
        null,
    );
}

/// Deep clone the redaction pattern.
pub fn clone(self: *const Redact, alloc: Allocator) Allocator.Error!Redact {
    return .{
        .regex = try alloc.dupe(u8, self.regex),
    };
}

/// Check if two redaction patterns are equal.
pub fn equal(self: *const Redact, other: *const Redact) bool {
    return std.mem.eql(u8, self.regex, other.regex);
}

/// A range within matched text that should be redacted.
pub const RedactedRange = struct {
    start: usize,
    end: usize,
};

/// Find all capture group ranges in the given text that should be redacted.
/// Returns ranges for capture groups 1+ (excludes group 0 which is the full match).
/// Caller owns the returned slice.
pub fn findRedactedRanges(
    self: *const Redact,
    alloc: Allocator,
    text: []const u8,
) ![]RedactedRange {
    var regex = self.oniRegex() catch return &.{};
    defer regex.deinit();

    var ranges = std.ArrayList(RedactedRange).init(alloc);
    errdefer ranges.deinit();

    var offset: usize = 0;
    while (offset < text.len) {
        var region = regex.search(text[offset..], .{}) catch |err| switch (err) {
            error.Mismatch => break,
            else => return err,
        };
        defer region.deinit();

        const starts = region.starts();
        const ends = region.ends();
        const count = region.count();

        // Skip group 0 (full match), only process capture groups 1+
        if (count > 1) {
            for (1..count) |i| {
                const start: usize = @intCast(starts[i]);
                const end: usize = @intCast(ends[i]);
                // Only add valid ranges (some groups may not participate in match)
                if (start < end) {
                    try ranges.append(.{
                        .start = offset + start,
                        .end = offset + end,
                    });
                }
            }
        }

        // Move past this match to find more
        const match_end: usize = @intCast(ends[0]);
        if (match_end == 0) {
            offset += 1; // Prevent infinite loop on zero-width match
        } else {
            offset += match_end;
        }
    }

    return ranges.toOwnedSlice();
}

// ============================================================================
// Tests
// ============================================================================

test "GitHub token - prefix visible, secret redacted" {
    const alloc = std.testing.allocator;

    const redact: Redact = .{ .regex = "ghp_([A-Za-z0-9_]+)" };
    const text = "token: ghp_abc123XYZ_secret";

    const ranges = try redact.findRedactedRanges(alloc, text);
    defer alloc.free(ranges);

    try std.testing.expectEqual(@as(usize, 1), ranges.len);
    // "ghp_" is 4 chars, starts at position 7 ("token: " = 7 chars)
    // So capture group starts at 7+4=11
    try std.testing.expectEqual(@as(usize, 11), ranges[0].start);
    try std.testing.expectEqual(@as(usize, 27), ranges[0].end);
    try std.testing.expectEqualStrings("abc123XYZ_secret", text[ranges[0].start..ranges[0].end]);
}

test "Bearer token - 'Bearer ' visible, token redacted" {
    const alloc = std.testing.allocator;

    const redact: Redact = .{ .regex = "Bearer ([A-Za-z0-9\\-_.~+/]+=*)" };
    const text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123";

    const ranges = try redact.findRedactedRanges(alloc, text);
    defer alloc.free(ranges);

    try std.testing.expectEqual(@as(usize, 1), ranges.len);
    // "Authorization: Bearer " = 22 chars
    try std.testing.expectEqual(@as(usize, 22), ranges[0].start);
    try std.testing.expectEqualStrings(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123",
        text[ranges[0].start..ranges[0].end],
    );
}

test "AWS access key - 'AKIA' visible, key ID redacted" {
    const alloc = std.testing.allocator;

    const redact: Redact = .{ .regex = "AKIA([A-Z0-9]{16})" };
    const text = "aws_key=AKIAIOSFODNN7EXAMPLE";

    const ranges = try redact.findRedactedRanges(alloc, text);
    defer alloc.free(ranges);

    try std.testing.expectEqual(@as(usize, 1), ranges.len);
    // "aws_key=AKIA" = 12 chars
    try std.testing.expectEqual(@as(usize, 12), ranges[0].start);
    try std.testing.expectEqual(@as(usize, 28), ranges[0].end);
    try std.testing.expectEqualStrings("IOSFODNN7EXAMPLE", text[ranges[0].start..ranges[0].end]);
}

test "Git URL with credentials - URL structure visible, user:pass redacted" {
    const alloc = std.testing.allocator;

    const redact: Redact = .{ .regex = "https://([^@]+)@github\\.com" };
    const text = "git clone https://user:secret_token@github.com/org/repo";

    const ranges = try redact.findRedactedRanges(alloc, text);
    defer alloc.free(ranges);

    try std.testing.expectEqual(@as(usize, 1), ranges.len);
    // "git clone https://" = 18 chars
    try std.testing.expectEqual(@as(usize, 18), ranges[0].start);
    try std.testing.expectEqualStrings("user:secret_token", text[ranges[0].start..ranges[0].end]);
}

test "multiple capture groups in single pattern" {
    const alloc = std.testing.allocator;

    // Pattern with two capture groups: redact both user and password separately
    const redact: Redact = .{ .regex = "https://([^:]+):([^@]+)@" };
    const text = "https://admin:p4ssw0rd@example.com";

    const ranges = try redact.findRedactedRanges(alloc, text);
    defer alloc.free(ranges);

    try std.testing.expectEqual(@as(usize, 2), ranges.len);
    try std.testing.expectEqualStrings("admin", text[ranges[0].start..ranges[0].end]);
    try std.testing.expectEqualStrings("p4ssw0rd", text[ranges[1].start..ranges[1].end]);
}

test "multiple matches in text" {
    const alloc = std.testing.allocator;

    const redact: Redact = .{ .regex = "ghp_([A-Za-z0-9]+)" };
    const text = "tokens: ghp_first123 and ghp_second456";

    const ranges = try redact.findRedactedRanges(alloc, text);
    defer alloc.free(ranges);

    try std.testing.expectEqual(@as(usize, 2), ranges.len);
    try std.testing.expectEqualStrings("first123", text[ranges[0].start..ranges[0].end]);
    try std.testing.expectEqualStrings("second456", text[ranges[1].start..ranges[1].end]);
}

test "no capture groups - nothing redacted" {
    const alloc = std.testing.allocator;

    // Pattern without capture groups - matches but redacts nothing
    const redact: Redact = .{ .regex = "ghp_[A-Za-z0-9]+" };
    const text = "token: ghp_abc123";

    const ranges = try redact.findRedactedRanges(alloc, text);
    defer alloc.free(ranges);

    try std.testing.expectEqual(@as(usize, 0), ranges.len);
}

test "no match - empty result" {
    const alloc = std.testing.allocator;

    const redact: Redact = .{ .regex = "ghp_([A-Za-z0-9]+)" };
    const text = "no tokens here";

    const ranges = try redact.findRedactedRanges(alloc, text);
    defer alloc.free(ranges);

    try std.testing.expectEqual(@as(usize, 0), ranges.len);
}

test "clone and equal" {
    const alloc = std.testing.allocator;

    const original: Redact = .{ .regex = "test_([a-z]+)" };
    const cloned = try original.clone(alloc);
    defer alloc.free(cloned.regex);

    try std.testing.expect(original.equal(&cloned));
    try std.testing.expect(cloned.equal(&original));

    const different: Redact = .{ .regex = "other_([a-z]+)" };
    try std.testing.expect(!original.equal(&different));
}

test "URL not affected by redaction pattern" {
    const alloc = std.testing.allocator;

    // Redaction pattern for git credentials should not affect plain URLs
    const redact: Redact = .{ .regex = "https://([^@]+)@github\\.com" };
    const plain_url = "https://github.com/ghostty-org/ghostty";

    const ranges = try redact.findRedactedRanges(alloc, plain_url);
    defer alloc.free(ranges);

    // No match because there's no @ in the URL
    try std.testing.expectEqual(@as(usize, 0), ranges.len);
}
