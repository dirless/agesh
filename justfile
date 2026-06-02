# agesh — build, test, and run recipes
#
# Prerequisites: just, crystal >= 1.20.0
# See `just --list` for available recipes.

# --- Settings ---
ncpus := `nproc`

# Release-mode compiler flags for production binaries.
#   --release   -O3 + single-module LTO across all files
#   --no-debug  strip debug info
#   --mcpu native  optimize for the exact CPU on this build machine
release_flags := "--release --no-debug --mcpu native"

# Output directory for binaries
bin_dir := "bin"

# --- List available recipes (runs when you type `just`) ---
list:
  @just --list

# --- Build both binaries (release) ---
build:
  @mkdir -p {{bin_dir}}
  crystal build src/cli/server.cr  -o {{bin_dir}}/agesh-server {{release_flags}} --threads {{ncpus}}
  crystal build src/cli/client.cr  -o {{bin_dir}}/agesh         {{release_flags}} --threads {{ncpus}}
  strip {{bin_dir}}/agesh-server {{bin_dir}}/agesh
  @echo "  ✓ Server  ({{bin_dir}}/agesh-server, $(ls -lh {{bin_dir}}/agesh-server | awk '{print $5}'))"
  @echo "  ✓ Client  ({{bin_dir}}/agesh, $(ls -lh {{bin_dir}}/agesh | awk '{print $5}'))"

# --- Run tests ---
spec:
  crystal spec --order random --threads {{ncpus}}

# --- Clean artifacts ---
clean:
  @rm -rf {{bin_dir}}/agesh-server {{bin_dir}}/agesh
  @rm -rf .crystal_cache
  @echo "  ✓ Cleaned"

# --- Run linter ---
lint:
  crystal tool format --check src/ spec/
  @command -v ameba >/dev/null 2>&1 && ameba src/ spec/ || echo "  ⚠ ameba not installed — skipping"

# --- Statically linked binaries ---
#
# Requires libzstd.a in .local/lib (Debian doesn't ship a static zstd library).
# Build from source:
#   git clone --depth 1 https://github.com/facebook/zstd.git /tmp/zstd
#   cd /tmp/zstd && make lib-release
#   mkdir -p .local/lib && cp lib/libzstd.a .local/lib/
build-static:
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p {{bin_dir}}
  if [[ ! -f .local/lib/libzstd.a ]]; then
    echo "  ⚠ .local/lib/libzstd.a not found — see justfile header for build instructions"
    exit 1
  fi
  # Use LIBRARY_PATH so the linker resolves -lzstd from our local static lib.
  # pkg-config gives the correct link-order for static OpenSSL.
  export LIBRARY_PATH="$PWD/.local/lib"
  static_link_flags="-L$PWD/.local/lib $(pkg-config --libs --static libcrypto 2>/dev/null || printf %s '-lz')"
  crystal build src/cli/server.cr  -o {{bin_dir}}/agesh-server {{release_flags}} --static --link-flags="$static_link_flags" --threads {{ncpus}}
  crystal build src/cli/client.cr  -o {{bin_dir}}/agesh         {{release_flags}} --static --link-flags="$static_link_flags" --threads {{ncpus}}
  strip {{bin_dir}}/agesh-server {{bin_dir}}/agesh
  echo "  ✓ Server  ({{bin_dir}}/agesh-server, static, $(ls -lh {{bin_dir}}/agesh-server | awk '{print $5}'))"
  echo "  ✓ Client  ({{bin_dir}}/agesh, static, $(ls -lh {{bin_dir}}/agesh | awk '{print $5}'))"

