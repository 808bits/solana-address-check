//! base58 decoding, the Bitcoin alphabet that Solana reuses for addresses.
//!
//! Zig's standard library has base64 but not base58, so this is the one piece
//! that has to be written by hand. Only decoding is needed to check an
//! address.
//!
//! base58 is base64 with the ambiguous glyphs removed: 0, O, I and l are gone,
//! as are + and /. There is no checksum. Bitcoin wraps base58 in base58check,
//! which appends four bytes of SHA-256, but a Solana address is the raw 32
//! byte public key and nothing else, which is why a typo cannot be detected
//! from the string alone.

const std = @import("std");

pub const Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub const Error = error{
    /// A character outside the base58 alphabet.
    InvalidCharacter,
    /// Decodes to some length other than 32 bytes.
    NotThirtyTwoBytes,
};

/// digit_table maps a byte to its base58 digit value, or -1 if it is not a
/// base58 character. Built at compile time so decoding is a table lookup
/// rather than a scan of the alphabet.
const digit_table = blk: {
    var table = [_]i8{-1} ** 256;
    for (Alphabet, 0..) |c, i| table[c] = @intCast(i);
    break :blk table;
};

/// decode32 parses a base58 string that must represent exactly 32 bytes,
/// which is what every Solana address is.
///
/// The string is one integer written in base 58, so decoding is repeated
/// multiply-by-58-and-add over a 32 byte accumulator. Leading zero bytes
/// vanish in that arithmetic, so they are counted separately as leading '1'
/// characters and the two halves have to add up to exactly 32. That last
/// requirement is what makes the encoding canonical: without it an address
/// could be padded with extra leading '1' characters and still decode.
pub fn decode32(s: []const u8) Error![32]u8 {
    var acc = [_]u8{0} ** 32;

    var leading_zeros: usize = 0;
    var seen_nonzero = false;

    for (s) |c| {
        const digit = digit_table[c];
        if (digit < 0) return error.InvalidCharacter;

        if (digit == 0 and !seen_nonzero) {
            leading_zeros += 1;
        } else {
            seen_nonzero = true;
        }

        // acc = acc*58 + digit, big endian, propagating the carry downward.
        var carry: u16 = @intCast(digit);
        var i: usize = acc.len;
        while (i > 0) {
            i -= 1;
            const v = @as(u16, acc[i]) * 58 + carry;
            acc[i] = @truncate(v);
            carry = v >> 8;
        }
        // A carry out of the top means the value needs more than 32 bytes.
        if (carry != 0) return error.NotThirtyTwoBytes;
    }

    // How many bytes the value actually occupies, ignoring leading zeros.
    var significant: usize = acc.len;
    for (acc) |b| {
        if (b != 0) break;
        significant -= 1;
    }

    if (leading_zeros + significant != 32) return error.NotThirtyTwoBytes;
    return acc;
}

test "decode32 round trips known addresses" {
    // The Solana System Program: 32 zero bytes, so 32 leading '1' characters.
    const system = try decode32("11111111111111111111111111111111");
    try std.testing.expectEqual([_]u8{0} ** 32, system);

    // An ordinary address, cross-checked against the Go implementation.
    const ordinary = try decode32("586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5");
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    try std.testing.expectEqual(want, ordinary);
}

test "decode32 rejects bad input" {
    // The four glyphs base58 leaves out, so that 0/O and I/l cannot be
    // confused when an address is read aloud or written down.
    try std.testing.expectError(error.InvalidCharacter, decode32("0OIl"));
    try std.testing.expectError(error.InvalidCharacter, decode32("hello world"));

    // Right alphabet, wrong length.
    try std.testing.expectError(error.NotThirtyTwoBytes, decode32(""));
    try std.testing.expectError(error.NotThirtyTwoBytes, decode32("11111"));
    try std.testing.expectError(error.NotThirtyTwoBytes, decode32("2"));

    // Padding a valid address with an extra leading '1' must not decode: that
    // would give one key two addresses.
    try std.testing.expectError(
        error.NotThirtyTwoBytes,
        decode32("1586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5"),
    );

    // Too large for 32 bytes.
    try std.testing.expectError(
        error.NotThirtyTwoBytes,
        decode32("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
    );
}

test "decode32 preserves leading zero bytes" {
    // These two come from the Go base58 encoder in the parent directory, which
    // is itself cross-checked against github.com/mr-tron/base58. A leading
    // zero byte is the case a plain integer conversion silently loses.
    const one_zero = try decode32("14uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofL");
    try std.testing.expectEqual([_]u8{0x00} ++ [_]u8{0xff} ** 31, one_zero);

    const two_zeros = try decode32("114RLsRs3EWcfh9dCSc8BuSPpvgwvuYqccbE1iLzskL");
    try std.testing.expectEqual([_]u8{0x00} ** 2 ++ [_]u8{0x11} ** 30, two_zeros);
}
