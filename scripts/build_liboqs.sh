#!/usr/bin/env bash
# Reproducible build of liboqs from source into ./vendor/liboqs-install.
# The exact git commit and CMake flags are written to vendor/liboqs-build-info.json
# and picked up by pqcap.env when results/env.json is produced.
set -euo pipefail

LIBOQS_TAG="${LIBOQS_TAG:-0.16.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor"
SRC="$VENDOR/liboqs"
BUILD="$VENDOR/liboqs-build"
PREFIX="$VENDOR/liboqs-install"

mkdir -p "$VENDOR"
if [ ! -d "$SRC/.git" ]; then
  git clone --depth 1 --branch "$LIBOQS_TAG" https://github.com/open-quantum-safe/liboqs.git "$SRC"
fi
COMMIT="$(git -C "$SRC" rev-parse HEAD)"

# Stateful hash-based signatures (LMS, XMSS) are compiled in so that their
# availability is decided by liboqs, not by us. Key/sign generation for stateful
# schemes is gated behind OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN;
# it is enabled ONLY for benchmarking (never for deployment: state reuse breaks security).
CMAKE_FLAGS=(
  -GNinja
  -DCMAKE_BUILD_TYPE=Release
  -DBUILD_SHARED_LIBS=ON
  -DOQS_BUILD_ONLY_LIB=ON
  -DOQS_DIST_BUILD=ON
  -DOQS_USE_OPENSSL=ON
  -DOQS_ENABLE_SIG_STFL_LMS=ON
  -DOQS_ENABLE_SIG_STFL_XMSS=ON
  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON
  -DCMAKE_INSTALL_PREFIX="$PREFIX"
)
if [ -d /opt/homebrew/opt/openssl@3 ]; then
  CMAKE_FLAGS+=(-DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3)
fi

cmake -S "$SRC" -B "$BUILD" "${CMAKE_FLAGS[@]}"
cmake --build "$BUILD" --parallel
cmake --install "$BUILD"

C_FLAGS="$(grep -E '^CMAKE_C_FLAGS_RELEASE:' "$BUILD/CMakeCache.txt" | cut -d= -f2- || true)"
COMPILER="$(grep -E '^CMAKE_C_COMPILER:' "$BUILD/CMakeCache.txt" | cut -d= -f2- || true)"
COMPILER_VERSION="$("$COMPILER" --version 2>/dev/null | head -1 || true)"

python3 - "$VENDOR/liboqs-build-info.json" <<PY
import json, sys
json.dump({
    "liboqs_tag": "$LIBOQS_TAG",
    "liboqs_commit": "$COMMIT",
    "cmake_flags": """${CMAKE_FLAGS[*]}""".split(),
    "c_compiler": "$COMPILER",
    "c_compiler_version": "$COMPILER_VERSION",
    "cmake_c_flags_release": "$C_FLAGS",
    "install_prefix": "$PREFIX",
}, open(sys.argv[1], "w"), indent=2)
PY
echo "liboqs $LIBOQS_TAG @ $COMMIT installed to $PREFIX"
