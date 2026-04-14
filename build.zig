const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // C libraries must not be compiled in Debug mode - Zig's C UB sanitizer
    // and glibc's _FORTIFY_SOURCE trip on C patterns in libbpf/libelf.
    const c_optimize: std.builtin.OptimizeMode = if (optimize == .Debug) .ReleaseFast else optimize;

    const libbpf_dep = b.dependency("libbpf", .{
        .target = target,
        .optimize = c_optimize,
    });

    // Step 1: Compile BPF program targeting bpfel-freestanding
    const bpf_prog = b.addObject(.{
        .name = "znitch_bpf",
        .root_source_file = null,
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .bpfel,
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseFast,
    });

    bpf_prog.addCSourceFile(.{
        .file = b.path("src/znitch.bpf.c"),
        .flags = &.{ "-g", "-O2", "-fno-asynchronous-unwind-tables" },
    });

    // BPF program needs libbpf's BPF-side headers
    const libbpf_artifact = libbpf_dep.artifact("bpf");
    bpf_prog.addIncludePath(libbpf_artifact.getEmittedIncludeTree());

    // Step 2: Build the userspace executable
    const exe = b.addExecutable(.{
        .name = "znitch",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Embed the compiled BPF object into the binary
    exe.root_module.addAnonymousImport("bpf_object", .{
        .root_source_file = bpf_prog.getEmittedBin(),
    });

    // Link against libbpf
    exe.linkLibrary(libbpf_artifact);
    exe.linkLibC();

    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run znitch");
    run_step.dependOn(&run_cmd.step);

    // Test step
    const dns_tests = b.addTest(.{
        .root_source_file = b.path("src/dns_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const dbus_tests = b.addTest(.{
        .root_source_file = b.path("src/dbus.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(dns_tests).step);
    test_step.dependOn(&b.addRunArtifact(dbus_tests).step);
}
