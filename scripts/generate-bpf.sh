#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

arch_include=""
target=""

if command -v gcc >/dev/null 2>&1; then
  gcc_triplet=$(gcc -dumpmachine)
  if [ -d "/usr/include/$gcc_triplet" ]; then
    arch_include="/usr/include/$gcc_triplet"
  fi
  case "$gcc_triplet" in
    x86_64-*|aarch64-*|arm64-*|riscv64-*|mips64el-*|mipsel-*|ppc64le-*|loongarch64-*) target="bpfel" ;;
    s390x-*|mips-*|mips64-*|ppc64-*) target="bpfeb" ;;
  esac
fi

if [ -z "$arch_include" ] && command -v clang >/dev/null 2>&1; then
  clang_triplet=$(clang -print-target-triple 2>/dev/null || true)
  if [ -n "$clang_triplet" ] && [ -d "/usr/include/$clang_triplet" ]; then
    arch_include="/usr/include/$clang_triplet"
  fi
  if [ -z "$target" ]; then
    case "$clang_triplet" in
      x86_64-*|aarch64-*|arm64-*|riscv64-*|mips64el-*|mipsel-*|ppc64le-*|loongarch64-*) target="bpfel" ;;
      s390x-*|mips-*|mips64-*|ppc64-*) target="bpfeb" ;;
    esac
  fi
fi

if [ -z "$arch_include" ]; then
  case "$(uname -m)" in
    x86_64)
      arch_include="/usr/include/x86_64-linux-gnu"
      target="bpfel"
      ;;
    aarch64|arm64)
      arch_include="/usr/include/aarch64-linux-gnu"
      target="bpfel"
      ;;
    *)
      echo "unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
fi

if [ ! -d "$arch_include" ]; then
  echo "missing arch include directory: $arch_include" >&2
  echo "install linux-libc-dev (Debian/Ubuntu) or linux-headers for your distro" >&2
  exit 1
fi

if [ -z "$target" ]; then
  echo "unable to determine bpf2go target architecture" >&2
  exit 1
fi

cd "$repo_root/internal/collector/ebpf"

go run github.com/cilium/ebpf/cmd/bpf2go \
  -cc clang \
  -target "$target" \
  -cflags "-O2 -g -Wall" \
  netwatch \
  ../../../bpf/netwatch.bpf.c \
  -- \
  -I/usr/include \
  -I"$arch_include"
