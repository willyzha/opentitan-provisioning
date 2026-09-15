# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Windows-only build workarounds, applied in the transition so that every
# artifact produced by `windows_binary` picks them up, while leaving the Linux
# host/server builds untouched.
#
# 1. `-DNDEBUG`: the crt toolchain never defines NDEBUG (not even in `-c opt`),
#    so shipped Windows artifacts would otherwise run with absl's mutex
#    deadlock detection and all DCHECKs enabled. Besides the cost, the
#    deadlock detector captures a stack trace on every `Mutex::Lock` via
#    `RtlCaptureStackBackTrace`, which is unsafe with `-fomit-frame-pointer`
#    code on non-Windows Win32 runtimes (it faults under wine).
#
# 2. `external/grpc.*@-fno-inline`: GCC 11.3.0 (MXE MinGW32, sjlj exceptions)
#    miscompiles gRPC's `CoreConfiguration` setup at -O1 and above. The
#    inlined `std::vector` walk in
#    `ServiceConfigParser::Builder::RegisterParser()` reads the parser list
#    before it is constructed and dereferences garbage, crashing
#    `grpc::CreateChannel()` with 0xC0000005. Blocking inlining in gRPC's own
#    sources avoids the bad codegen. See docs/windows_ate_dll.md.
WINDOWS_COPTS = ["-DNDEBUG"]

WINDOWS_PER_FILE_COPTS = ["external/grpc.*@-fno-inline"]

def _windows_platform_transition_impl(settings, attr):
    return {
        "//command_line_option:platforms": "//third_party/crt/platforms/x86_32:win32",
        "//command_line_option:copt": settings["//command_line_option:copt"] + WINDOWS_COPTS,
        "//command_line_option:per_file_copt": settings["//command_line_option:per_file_copt"] + WINDOWS_PER_FILE_COPTS,
    }

windows_platform_transition = transition(
    implementation = _windows_platform_transition_impl,
    inputs = [
        "//command_line_option:copt",
        "//command_line_option:per_file_copt",
    ],
    outputs = [
        "//command_line_option:platforms",
        "//command_line_option:copt",
        "//command_line_option:per_file_copt",
    ],
)

def _windows_binary_impl(ctx):
    # The dependency 'dep' is now built in the windows configuration.
    # ctx.attr.dep is a list because the transition is 1:1.
    dep = ctx.attr.dep[0]

    # Determine the output file name based on the target name. DLLs are
    # produced by cc_binary targets with linkshared = True, executables by
    # regular cc_binary targets.
    extension = ctx.attr.extension
    output = ctx.actions.declare_file(ctx.label.name + "." + extension)

    found = False
    for f in dep[DefaultInfo].files.to_list():
        if f.extension == extension:
            ctx.actions.symlink(output = output, target_file = f)
            found = True
            break

    if not found:
        fail("Could not find .{} in dependency output. Files: {}".format(
            extension,
            str(dep[DefaultInfo].files.to_list()),
        ))

    return [
        DefaultInfo(
            files = depset([output]),
            runfiles = dep[DefaultInfo].default_runfiles,
        ),
    ]

windows_binary = rule(
    implementation = _windows_binary_impl,
    attrs = {
        "dep": attr.label(cfg = windows_platform_transition),
        "extension": attr.string(
            default = "dll",
            values = ["dll", "exe"],
            doc = "Artifact extension produced by `dep`.",
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
