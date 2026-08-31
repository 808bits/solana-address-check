//! WebAssembly build of the address checker.
//!
//! The interface is deliberately tiny, because passing strings across the
//! WASM boundary means passing offsets into linear memory and nothing else.
//! The flow from JavaScript is:
//!
//!     const ptr = wasm.addressBuffer();
//!     // write UTF-8 bytes of the address at ptr
//!     const len = wasm.check(addressLength);
//!     // read len bytes of report from wasm.reportBuffer()
//!     const kind = wasm.lastKind();
//!
//! Both buffers are static, so the module needs no allocator and no imports
//! at all. It runs on wasm32-freestanding: no WASI, no host functions.

const std = @import("std");
const address = @import("address.zig");

/// Freestanding has no place to print a panic message, so trap instead. This
/// should be unreachable: classify returns errors as values.
pub const panic = std.debug.FullPanic(struct {
    fn trap(msg: []const u8, first_trace_addr: ?usize) noreturn {
        _ = msg;
        _ = first_trace_addr;
        @trap();
    }
}.trap);

/// Longer than any base58 string that could decode to 32 bytes, with room for
/// a caller to pass something silly and get a clean "not an address" answer.
var address_buffer: [256]u8 = undefined;
var report_buffer: [8192]u8 = undefined;
var last_kind: u32 = 0;

/// addressBuffer returns where to write the address, as UTF-8, before calling
/// check.
export fn addressBuffer() [*]u8 {
    return &address_buffer;
}

/// addressCapacity is the most bytes addressBuffer can hold.
export fn addressCapacity() usize {
    return address_buffer.len;
}

/// reportBuffer returns where the explanation was written by check.
export fn reportBuffer() [*]const u8 {
    return &report_buffer;
}

/// check classifies the first len bytes of addressBuffer and writes the full
/// explanation into reportBuffer, returning its length in bytes.
export fn check(len: usize) usize {
    const input = address_buffer[0..@min(len, address_buffer.len)];

    const result = address.classify(input);
    last_kind = @intFromEnum(result.kind);

    var w = std.Io.Writer.fixed(&report_buffer);
    address.report(&w, input, result) catch {
        // The only way to fail is running out of room, which would mean the
        // report grew past 8 KB. Report what fits rather than losing it all.
        return w.end;
    };
    return w.end;
}

/// lastKind returns the classification from the most recent check, as the
/// ordinal of address.Kind: 0 invalid, 1 off curve, 2 small order, 3 torsion,
/// 4 signer. Useful for styling the result without parsing the text.
export fn lastKind() u32 {
    return last_kind;
}

/// canHavePrivateKey returns 1 if the most recent check found an address that
/// could have a key, and 0 otherwise.
export fn canHavePrivateKey() u32 {
    const kind: address.Kind = @enumFromInt(last_kind);
    return if (kind.canHavePrivateKey()) 1 else 0;
}

test "the exported flow produces a report" {
    const input = "11111111111111111111111111111111";
    @memcpy(address_buffer[0..input.len], input);

    const len = check(input.len);
    try std.testing.expect(len > 0);

    const text = report_buffer[0..len];
    try std.testing.expect(std.mem.indexOf(u8, text, "small order") != null);
    try std.testing.expectEqual(@intFromEnum(address.Kind.small_order), lastKind());
    try std.testing.expectEqual(@as(u32, 0), canHavePrivateKey());
}

test "a signer address reports as such" {
    const input = "586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5";
    @memcpy(address_buffer[0..input.len], input);

    const len = check(input.len);
    const text = report_buffer[0..len];
    try std.testing.expect(std.mem.indexOf(u8, text, "prime-order subgroup") != null);
    try std.testing.expectEqual(@as(u32, 1), canHavePrivateKey());
}

test "an oversized length is clamped rather than read out of bounds" {
    const len = check(address_buffer.len * 10);
    try std.testing.expect(len > 0);
}
