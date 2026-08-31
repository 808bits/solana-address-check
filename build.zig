const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The CLI.
    const exe = b.addExecutable(.{
        .name = "solana-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Check an address: zig build run -- <address>").dependOn(&run.step);

    // The WebAssembly build. Freestanding rather than WASI: the module takes
    // no imports at all, so it runs in a browser with nothing to provide.
    const wasm = b.addExecutable(.{
        .name = "solana-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wasm.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .wasm32,
                .os_tag = .freestanding,
            }),
            // Size matters more than speed for something fetched over a
            // network, and the curve arithmetic is fast either way.
            .optimize = .ReleaseSmall,
        }),
    });
    // No main, just the exported functions.
    wasm.entry = .disabled;
    wasm.rdynamic = true;

    const install_wasm = b.addInstallFileWithDir(
        wasm.getEmittedBin(),
        .{ .custom = "../web" },
        "solana-check.wasm",
    );
    b.step("wasm", "Build the WebAssembly module into web/").dependOn(&install_wasm.step);

    // Tests, covering the shared code plus the exported WASM entry points.
    const test_step = b.step("test", "Run the tests");
    for ([_][]const u8{ "src/base58.zig", "src/address.zig", "src/wasm.zig" }) |path| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}
