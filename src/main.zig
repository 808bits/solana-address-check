//! solana-check: does this Solana address have a private key?
//!
//!     solana-check <address>
//!
//! There are no flags. The reasoning is always printed, because a bare yes or
//! no invites trusting the tool rather than the argument, and the argument is
//! short enough to read.
//!
//! Exit status is 0 when the address can have a private key, 1 when it cannot
//! or the input is not an address, so this works as a guard in a script.

const std = @import("std");
const address = @import("address.zig");

pub fn main(init: std.process.Init) !u8 {
    var out_buf: [4096]u8 = undefined;
    var out_writer = std.Io.File.stdout().writer(init.io, &out_buf);
    const out = &out_writer.interface;
    defer out.flush() catch {};

    var args = std.process.Args.Iterator.init(init.minimal.args);
    const program = args.next() orelse "solana-check";

    const arg = args.next() orelse {
        try out.print("usage: {s} <solana address>\n\n", .{program});
        try out.print("Reports whether an address can have a private key, and why.\n", .{});
        try out.print("Exits 1 if it cannot.\n", .{});
        return 1;
    };
    if (args.next() != null) {
        try out.print("error: expected exactly one address\n", .{});
        return 1;
    }

    const result = address.classify(arg);
    try address.report(out, arg, result);

    return if (result.kind.canHavePrivateKey()) 0 else 1;
}
