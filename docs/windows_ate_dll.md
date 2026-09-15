# Windows ATE DLL: toolchain notes

The Win32 ATE client (`//src/ate:ate`, packaged by `//src/ate:windows`) is
cross-compiled with the MXE MinGW32 toolchain pinned in `MODULE.bazel`
(`lowRISC/crt` v0.4.14, `mxe-binaries-win32.tar.xz`). That toolchain is
**GCC 11.3.0**, 32-bit, configured with `--enable-sjlj-exceptions`.

Two toolchain-level problems affect this artifact. Both are worked around in
the platform transition in [`//rules:windows_binary.bzl`](../rules/windows_binary.bzl),
so they apply to Windows artifacts only and leave the Linux server builds
alone. `//src/ate/test_programs:ate_dll_smoke_test` guards against
regressions.

## 1. GCC miscompiles gRPC's `CoreConfiguration` setup

**Symptom.** `CreateClient()` crashes with an access violation (`0xC0000005`)
inside `grpc::CreateChannel()`, before any network connection is attempted.
Originally reported by Nuvoton against their ATE client fork, which shares
this toolchain, this gRPC version (1.68) and this client code.

**Call path.**

```
grpc_core::CoreConfiguration::BuildNewAndMaybeSet()
  CoreConfiguration::Builder::Builder()
    BuildCoreConfiguration()
      RegisterExtraFilters()
        RegisterBackendMetricFilter()
          GcpAuthenticationFilterRegister()
            GcpAuthenticationServiceConfigParser::Register()
              ServiceConfigParser::Builder::RegisterParser()   <-- faults
```

**Bad codegen.** At `-O1` and above GCC inlines the `std::vector` accessors of
the parser registry into `RegisterParser()` as raw memory loads, and the read
gets scheduled ahead of the initialization of those pointers. The loop then
walks a garbage range and calls through a garbage vtable:

```asm
addl $0x4,-0x50(%ebp)   ; ++it            ─┐  inlined begin()/end() walk
mov  -0x50(%ebp),%eax   ; it               │
cmp  %eax,-0x5c(%ebp)   ; it != end()     ─┘
...
mov  -0x50(%ebp),%edx
mov  (%edx),%ecx        ; parser pointer  (garbage)
mov  (%ecx),%eax        ; vtable          (garbage, e.g. 0x00000004)
call *0x8(%eax)         ; <-- 0xC0000005 reading 0x0000000c
```

The most likely culprit is the interaction with GCC's setjmp/longjmp exception
bookkeeping on 32-bit MinGW, a historically fragile area of the optimizer.

**Workaround.** `--per_file_copt=external/grpc.*@-fno-inline`, scoped to gRPC's
own sources. Keeping the accessors as real calls prevents the reordering.

> [!NOTE]
> `-O1` is not a safe harbour: the crt `fastbuild` feature is `-O1 -g3`, so the
> **default** build is affected. `-c opt` (`-O2 -finline-small-functions
> -flto`) is worse, not better.

Ruled out by Nuvoton (each rebuilt and re-run, not just reasoned about):
`-mstackrealign`, `-fno-strict-aliasing`, `-fno-lifetime-dse`, `-O1`.
`-O0` on gRPC also works but de-optimizes everything.

## 2. The crt toolchain never defines `NDEBUG`

`grep -rn NDEBUG third_party/crt/` returns nothing: unlike Bazel's stock
Unix C++ toolchain, the crt feature sets do not add `-DNDEBUG` in *any*
compilation mode, including `-c opt`. Shipped Windows artifacts therefore run
with:

- absl mutex **deadlock detection** enabled, which captures a full stack trace
  via `RtlCaptureStackBackTrace` on every `Mutex::Lock`, and
- all `DCHECK`s in gRPC/protobuf/absl enabled.

Besides the runtime cost, the stack capture is what makes the DLL crash under
wine: wine's i386 `RtlCaptureStackBackTrace` walks the `EBP` chain, and code
built with `-fomit-frame-pointer` (the default at `-O1`+) leaves a non-pointer
in `EBP`. Real Windows validates the frames, so this particular crash is not
seen on hardware — it only masks issue #1 when testing under wine.

## Testing the DLL: the simulated Windows ATE machine

Both tests run the DLL inside a container that stands in for a Windows ATE
machine, so nothing Windows-specific has to be installed on the host — only
`podman`. The image comes in two layers:

| Layer | Built by | Contents |
| --- | --- | --- |
| `ot-prov-ate-client` | [`util/containers/ate_client/Dockerfile`](../util/containers/ate_client/Dockerfile) | Debian + Wine + a pre-initialized prefix |
| `localhost/ate_client` | [`Dockerfile.bundle`](../util/containers/ate_client/Dockerfile.bundle) | the above + the freshly built Windows bundle |

The base layer is cached across runs (the tests build it on first use); only the
bundle layer is rebuilt when the DLL changes.

### Hermetic smoke test

```sh
bazelisk test //src/ate/test_programs:ate_dll_smoke_test --test_output=all
```

The test loads the packaged `ate.dll` with `LoadLibrary()` and calls
`CreateClient()` in both insecure and mTLS mode. No provisioning appliance is
required: channel creation is lazy, so reaching a live `AteClient` is enough
to prove the gRPC configuration path is not miscompiled. The container runs
with `--network=none`. An access violation is reported by the harness as exit
code 42 with the faulting address.

### Integration test

```sh
./tests/run_ate_dll_test.sh          # RSA
./tests/run_ate_dll_test.sh --pq     # ML-KEM / ML-DSA
```

This is the Win32 counterpart of `tests/run_tls_test.sh`: it deploys the full
appliance and then performs a real `InitSession` RPC from the ATE container,
which runs in its own network namespace and dials the PA through podman's
`host.containers.internal` alias. The test exports `OTPROV_DNS_PA` before
deploying so that alias lands in the PA certificate's SAN list; if the alias is
unavailable the test falls back to host networking and loopback.

### Debugging a failure

`winedbg` is impractically slow on a ~20 MB DLL. Instead, the harness prints
the register state, the module map and a stack scan of return addresses inside
`ate.dll`; resolve those offsets against the DLL's `ImageBase` (`objdump -p`)
with `nm`/`addr2line` from the MXE toolchain:

```sh
MXE=$(bazel info output_base)/external/+_repo_rules+gcc_mxe_mingw32_files
$MXE/bin/i686-w64-mingw32.shared-nm --numeric-sort --defined-only ate.dll
```

To poke around inside the ATE machine itself:

```sh
podman run --rm -it --entrypoint=/bin/bash localhost/ate_client:latest
```

