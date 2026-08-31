//! Classifying a Solana address: can it have a private key at all?
//!
//! A Solana address is the base58 of a 32 byte Ed25519 public key. There is no
//! version byte, no checksum and no hashing step. Where a Bitcoin or Ethereum
//! address is a hash of the public key, a Solana address IS the public key, so
//! this question can be answered by arithmetic alone, with nothing to look up.
//!
//! Everything below the base58 decoding comes from Zig's standard library,
//! which exports the curve operations directly as std.crypto.ecc.Edwards25519.
//! Go's standard library does not: the same arithmetic lives there in an
//! internal package that cannot be imported.

const std = @import("std");
const base58 = @import("base58.zig");

const Ed = std.crypto.ecc.Edwards25519;

/// The encoding of the identity element: y = 1 little endian, sign bit clear.
const identity_encoding = [_]u8{1} ++ [_]u8{0} ** 31;

/// L, the order of the prime-order subgroup, as a little endian scalar.
const group_order = blk: {
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, Ed.scalar.field_order, .little);
    break :blk b;
};

/// Kind is what an address is capable of. The order is the order the checks
/// are made in, each one ruling out a way of having a key.
pub const Kind = enum {
    /// Not 32 bytes of base58, so not an address at all. The only case a
    /// wallet can catch on its own.
    invalid,

    /// 32 well formed bytes naming no point on the curve. Every public key is
    /// a*B and every a*B is on the curve, so no private key exists. Provable,
    /// not merely hard. Program derived addresses are deliberately like this,
    /// so that only the owning program can act for them.
    off_curve,

    /// One of the 8 points of order 1, 2, 4 or 8. Anyone can forge a signature
    /// for these without knowing a secret, so a signature over such an address
    /// proves nothing. The Solana System Program address is one of them.
    small_order,

    /// A real curve point carrying a torsion component, so it is not a
    /// multiple of the base point. B has prime order L, so a*B never has one.
    /// No private key exists, provably, one layer deeper than off_curve.
    torsion,

    /// A point in the prime-order subgroup, the only kind a keypair produces.
    /// A scalar for it exists. Whether anyone holds it is another matter.
    signer,

    /// Whether any scalar at all maps to this address.
    ///
    /// Small-order addresses are excluded deliberately: the identity
    /// technically has the scalar 0, but no seed produces it and anyone can
    /// forge for it, so calling it key-bearing would mislead.
    pub fn canHavePrivateKey(k: Kind) bool {
        return k == .signer;
    }

    pub fn summary(k: Kind) []const u8 {
        return switch (k) {
            .invalid => "not a valid address",
            .off_curve => "off the curve",
            .small_order => "small order",
            .torsion => "on the curve, with a torsion component",
            .signer => "in the prime-order subgroup",
        };
    }

    pub fn why(k: Kind) []const u8 {
        return switch (k) {
            .invalid => "not 32 bytes of base58, so no wallet will send to it",
            .off_curve => "no private key can exist, provably: the bytes are not a curve point, which is what a program derived address looks like",
            .small_order => "anyone can forge a signature for this address, so a signature over it proves nothing",
            .torsion => "no private key can exist, provably: the point is not a multiple of the base point",
            .signer => "a private key exists mathematically, though recovering it from the address alone is a ~2^126 discrete logarithm",
        };
    }
};

/// Reason records which check settled the verdict, so the explanation can say
/// what actually happened rather than only what the answer was.
pub const Reason = enum {
    bad_character,
    wrong_length,
    non_canonical,
    no_square_root,
    sign_bit_on_zero_x,
    low_order,
    not_in_subgroup,
    in_subgroup,
};

pub const Result = struct {
    kind: Kind,
    reason: Reason,
    /// The decoded key. Meaningless when kind is .invalid.
    bytes: [32]u8,
};

/// classify answers the question, in the cheapest order that can settle it.
pub fn classify(address: []const u8) Result {
    const bytes = base58.decode32(address) catch |err| return .{
        .kind = .invalid,
        .reason = switch (err) {
            error.InvalidCharacter => .bad_character,
            error.NotThirtyTwoBytes => .wrong_length,
        },
        .bytes = [_]u8{0} ** 32,
    };

    // fromBytes does not check that y is reduced, so ask separately. Without
    // this, one key could have two encodings and therefore two addresses.
    Ed.rejectNonCanonical(bytes) catch return .{
        .kind = .off_curve,
        .reason = .non_canonical,
        .bytes = bytes,
    };

    // Decompression: solve x^2 = (y^2 - 1) / (d*y^2 + 1). That has a solution
    // for only about half of all y, which is why about half of all 32 byte
    // strings are not public keys.
    const point = Ed.fromBytes(bytes) catch return .{
        .kind = .off_curve,
        .reason = .no_square_root,
        .bytes = bytes,
    };

    // Re-encoding has to reproduce the input exactly. With y already known to
    // be reduced, the one remaining way it cannot is a sign bit set on a point
    // whose x is zero: zero has no sign, so both encodings name the same
    // point. fromBytes accepts that quietly, negating zero to zero, which
    // would give one key two addresses.
    if (!std.mem.eql(u8, &point.toBytes(), &bytes)) return .{
        .kind = .off_curve,
        .reason = .sign_bit_on_zero_x,
        .bytes = bytes,
    };

    // rejectLowOrder covers all 8 torsion points. Checked before subgroup
    // membership because the identity is in the subgroup, yet forgeability is
    // the more important fact about it.
    point.rejectLowOrder() catch return .{
        .kind = .small_order,
        .reason = .low_order,
        .bytes = bytes,
    };

    if (!inPrimeOrderSubgroup(point)) return .{
        .kind = .torsion,
        .reason = .not_in_subgroup,
        .bytes = bytes,
    };

    return .{ .kind = .signer, .reason = .in_subgroup, .bytes = bytes };
}

/// inPrimeOrderSubgroup reports whether L*P is the identity, which is exactly
/// what it means for P to be a multiple of the base point.
///
/// Ed.mul would also answer this, since it reports an identity result as an
/// error, but reading a success out of an error is a poor way to say what is
/// meant. Double-and-add over the stdlib point operations is clearer and the
/// addition law is complete, so no case needs special handling.
fn inPrimeOrderSubgroup(p: Ed) bool {
    var result = Ed.identityElement;

    var i: usize = 256;
    while (i > 0) {
        i -= 1;
        result = result.dbl();
        const byte = group_order[i / 8];
        if ((byte >> @intCast(i % 8)) & 1 == 1) {
            result = result.add(p);
        }
    }

    return std.mem.eql(u8, &result.toBytes(), &identity_encoding);
}

/// report writes the verdict and the reasoning behind it. There is no quiet
/// mode: the explanation is the point, and a bare yes or no invites trusting
/// the tool instead of the argument.
pub fn report(w: *std.Io.Writer, address: []const u8, r: Result) !void {
    try w.print("address          {s}\n", .{address});
    if (r.kind != .invalid) {
        try w.print("bytes            {x}\n", .{r.bytes});
    }
    try w.print("classification   {s}\n", .{r.kind.summary()});
    try w.print("can have a key   {s}\n", .{if (r.kind.canHavePrivateKey()) "yes" else "no"});
    try w.print("why              {s}\n", .{r.kind.why()});

    try w.print("\nhow that was decided\n", .{});
    try w.print("  a Solana address IS the 32 byte public key, so this is pure\n", .{});
    try w.print("  arithmetic, with nothing to look up\n\n", .{});

    // Step 1, always reached.
    switch (r.reason) {
        .bad_character => {
            try w.print("  1. is it base58?                 NO\n", .{});
            try w.print("     base58 leaves out 0, O, I and l so that an address survives\n", .{});
            try w.print("     being read aloud. This string uses a character outside it.\n", .{});
            return;
        },
        .wrong_length => {
            try w.print("  1. does it decode to 32 bytes?   NO\n", .{});
            try w.print("     an address is a 32 byte public key and nothing else, so any\n", .{});
            try w.print("     other length is not an address. Leading '1' characters count\n", .{});
            try w.print("     as leading zero bytes, and padding with extra ones is refused\n", .{});
            try w.print("     so that one key cannot have two addresses.\n", .{});
            return;
        },
        else => try w.print("  1. does it decode to 32 bytes?   yes\n", .{}),
    }

    // Step 2.
    if (r.reason == .non_canonical) {
        try w.print("  2. is y below 2^255-19?          NO\n", .{});
        try w.print("     the 32 bytes hold y in little endian with the sign of x in the\n", .{});
        try w.print("     top bit, and y must be reduced modulo the field prime. An\n", .{});
        try w.print("     unreduced y would give one point a second encoding, and so a\n", .{});
        try w.print("     second address.\n", .{});
        return;
    }
    try w.print("  2. is y below 2^255-19?          yes\n", .{});

    // Step 3.
    if (r.reason == .no_square_root) {
        try w.print("  3. is it a point on the curve?   NO\n", .{});
        try w.print("     recovering x means solving x^2 = (y^2-1)/(d*y^2+1), and that\n", .{});
        try w.print("     ratio is a square for only about half of all y. For this y it\n", .{});
        try w.print("     is not, so these bytes name no point at all.\n", .{});
        try w.print("     Every public key is a*B and every a*B is on the curve, so the\n", .{});
        try w.print("     search for a matching key is a search over an empty set. That\n", .{});
        try w.print("     is not \"too hard to find\", it is \"cannot exist\".\n", .{});
        return;
    }
    if (r.reason == .sign_bit_on_zero_x) {
        try w.print("  3. is it a point on the curve?   NO, not canonically\n", .{});
        try w.print("     these bytes decode to a point whose x is zero, and zero has no\n", .{});
        try w.print("     sign, so the top bit means nothing there. Setting it produces a\n", .{});
        try w.print("     second encoding of a point that already has one. Refused, so\n", .{});
        try w.print("     that one key cannot have two addresses.\n", .{});
        return;
    }
    try w.print("  3. is it a point on the curve?   yes\n", .{});

    // Step 4.
    if (r.reason == .low_order) {
        try w.print("  4. is it small order?            YES\n", .{});
        try w.print("     8*A is the identity, so A is one of only 8 points on the curve.\n", .{});
        try w.print("     Verification checks S*B == R + k*A. Taking R = r*B and S = r\n", .{});
        try w.print("     collapses that to k*A == identity, which holds whenever the\n", .{});
        try w.print("     order divides k, so a forger re-rolls r a handful of times and\n", .{});
        try w.print("     signs without knowing any secret.\n", .{});
        try w.print("     The Solana System Program address is one of these 8.\n", .{});
        return;
    }
    try w.print("  4. is it small order?            no\n", .{});

    // Step 5.
    if (r.reason == .not_in_subgroup) {
        try w.print("  5. is L*A the identity?          NO\n", .{});
        try w.print("     so A carries a torsion component and is not a multiple of the\n", .{});
        try w.print("     base point. B has prime order L, so a*B never has one.\n", .{});
        try w.print("     The curve has 8*L points and only L of them are reachable, so\n", .{});
        try w.print("     about 7 in 8 curve points land here. No key exists, provably.\n", .{});
        return;
    }
    try w.print("  5. is L*A the identity?          yes, so A = a*B for some scalar a\n", .{});
    try w.print("     that scalar exists and is one definite number below L. Recovering\n", .{});
    try w.print("     it from A is the discrete logarithm problem, about 2^126\n", .{});
    try w.print("     operations, with no partial credit along the way.\n", .{});
    try w.print("     Roughly half of these points have no seed at all, because clamping\n", .{});
    try w.print("     restricts scalars to about half the subgroup.\n", .{});
}

const testing = std.testing;

test "an ordinary address is a signer" {
    const r = classify("586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5");
    try testing.expectEqual(Kind.signer, r.kind);
    try testing.expectEqual(Reason.in_subgroup, r.reason);
    try testing.expect(r.kind.canHavePrivateKey());
}

test "the System Program is small order" {
    const r = classify("11111111111111111111111111111111");
    try testing.expectEqual(Kind.small_order, r.kind);
    try testing.expect(!r.kind.canHavePrivateKey());
}

test "all 8 small-order points are caught" {
    // The complete torsion subgroup, the same table the Go tests pin.
    const encodings = [_][]const u8{
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    };
    for (encodings) |hex| {
        var raw: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&raw, hex);

        const point = try Ed.fromBytes(raw);
        // Small order means order divides 8, so 8*P is the identity.
        try testing.expectEqualSlices(
            u8,
            &identity_encoding,
            &point.clearCofactor().toBytes(),
        );
        try testing.expectError(error.WeakPublicKey, point.rejectLowOrder());
    }
}

test "a sign bit on a point whose x is zero is refused" {
    // Only two points have x = 0: the identity (y = 1) and the order-2 point
    // (y = -1). For those the top bit is meaningless, so the variant with it
    // set is a second encoding of the same point and must not be accepted.
    // std.crypto's fromBytes accepts them, negating zero to zero, so this is
    // checked separately. The Go implementation next door rejects them too.
    const pairs = [_]struct { canonical: []const u8, bogus: []const u8 }{
        .{
            .canonical = "0100000000000000000000000000000000000000000000000000000000000000",
            .bogus = "0100000000000000000000000000000000000000000000000000000000000080",
        },
        .{
            .canonical = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            .bogus = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        },
    };

    for (pairs) |pair| {
        var canonical: [32]u8 = undefined;
        var bogus: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&canonical, pair.canonical);
        _ = try std.fmt.hexToBytes(&bogus, pair.bogus);

        // Both decode to the same point, which is exactly the problem.
        const a = try Ed.fromBytes(canonical);
        const b = try Ed.fromBytes(bogus);
        try testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());

        // Only the canonical one may be treated as a real encoding.
        var buf: [64]u8 = undefined;
        const canonical_kind = classify(base58Encode(&buf, canonical));
        try testing.expectEqual(Kind.small_order, canonical_kind.kind);

        const bogus_result = classify(base58Encode(&buf, bogus));
        try testing.expectEqual(Kind.off_curve, bogus_result.kind);
        try testing.expectEqual(Reason.sign_bit_on_zero_x, bogus_result.reason);
    }
}

test "re-encoding a normal address reproduces it exactly" {
    // The canonicality check must not reject anything legitimate.
    var seed: [32]u8 = undefined;
    for (0..16) |i| {
        @memset(&seed, @intCast(i + 1));
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        const encoded = kp.public_key.toBytes();

        const point = try Ed.fromBytes(encoded);
        try testing.expectEqualSlices(u8, &encoded, &point.toBytes());

        var buf: [64]u8 = undefined;
        try testing.expectEqual(Kind.signer, classify(base58Encode(&buf, encoded)).kind);
    }
}

test "malformed input is invalid, not off curve" {
    try testing.expectEqual(Kind.invalid, classify("").kind);
    try testing.expectEqual(Kind.invalid, classify("0OIl").kind);
    try testing.expectEqual(Kind.invalid, classify("11111").kind);
    try testing.expectEqual(Reason.bad_character, classify("0OIl").reason);
    try testing.expectEqual(Reason.wrong_length, classify("11111").reason);
}

test "the base point is a signer, and its negation too" {
    // B itself is a valid public key: it is 1*B.
    var buf: [64]u8 = undefined;
    const encoded = base58Encode(&buf, Ed.basePoint.toBytes());
    const r = classify(encoded);
    try testing.expectEqual(Kind.signer, r.kind);

    // Negating flips the sign bit of x, and -B = (L-1)*B is still a multiple
    // of B, so it stays a signer.
    const neg = classify(base58Encode(&buf, Ed.basePoint.neg().toBytes()));
    try testing.expectEqual(Kind.signer, neg.kind);
}

test "subgroup membership matches the standard library" {
    // Ed.mul reports an identity result as an error, so it answers the same
    // question by a different route. The two must never disagree.
    var seed: [32]u8 = undefined;
    for (0..8) |i| {
        @memset(&seed, @intCast(i + 1));
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        const point = try Ed.fromBytes(kp.public_key.toBytes());

        const ours = inPrimeOrderSubgroup(point);
        const theirs = if (point.mul(group_order)) |_| false else |err| switch (err) {
            error.IdentityElement => true,
            else => false,
        };
        try testing.expectEqual(theirs, ours);
        try testing.expect(ours); // a real public key is always in the subgroup
    }
}

/// base58Encode is test-only: the checker never needs to encode, but a couple
/// of tests want to feed a computed point back through classify.
fn base58Encode(buf: []u8, bytes: [32]u8) []const u8 {
    var digits: [64]u8 = undefined;
    var len: usize = 0;

    for (bytes) |b| {
        var carry: u16 = b;
        for (digits[0..len]) |*d| {
            const v = @as(u16, d.*) * 256 + carry;
            d.* = @intCast(v % 58);
            carry = v / 58;
        }
        while (carry > 0) {
            digits[len] = @intCast(carry % 58);
            carry /= 58;
            len += 1;
        }
    }

    var out: usize = 0;
    for (bytes) |b| {
        if (b != 0) break;
        buf[out] = base58.Alphabet[0];
        out += 1;
    }
    var i = len;
    while (i > 0) {
        i -= 1;
        buf[out] = base58.Alphabet[digits[i]];
        out += 1;
    }
    return buf[0..out];
}
