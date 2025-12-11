#!/bin/bash
set -e

# 1. Auto-discover the REAL Clang binary inside the sandbox
#    (Handles variations like external/llvm... or ../external/llvm...)
REAL_CLANG=$(find . -name clang -type f -executable | grep "bin/clang" | head -n 1)

if [ -z "$REAL_CLANG" ]; then
    echo "WRAPPER ERROR: Could not find 'clang' binary in the sandbox." >&2
    echo "Sandbox contents (binaries):" >&2
    find . -name "*clang*" -type f -executable >&2
    exit 1
fi

# 2. Auto-discover the resource directory (where stddef.h lives)
#    We look for the pattern "lib/clang/<version>/include/stddef.h"
STDDEF_PATH=$(find . -name stddef.h | grep "lib/clang" | head -n 1)

if [ -z "$STDDEF_PATH" ]; then
    echo "WRAPPER ERROR: Could not find 'stddef.h' in the sandbox." >&2
    echo "This means the toolchain files are not being copied into the sandbox." >&2
    echo "Ensure 'data' in toolchain/BUILD.bazel includes the filegroup." >&2
    exit 1
fi

# Get the directory containing stddef.h
RESOURCE_DIR=$(dirname "$STDDEF_PATH")

# 3. Execute Clang with the explicit resource directory
#    -resource-dir: Tells Clang exactly where its internal headers are.
exec "$REAL_CLANG" -no-canonical-prefixes -resource-dir "$RESOURCE_DIR" "$@"