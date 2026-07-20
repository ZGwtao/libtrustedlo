#!/usr/bin/env bash
set -euo pipefail

: "${MICROKIT_SDK:?MICROKIT_SDK must be set}"

TARGET="${TARGET:-aarch64}"
CPU="${CPU:-cortex-a53}"
MICROKIT_BOARD="${MICROKIT_BOARD:-qemu_virt_aarch64}"
MICROKIT_CONFIG="${MICROKIT_CONFIG:-debug}"
BUILD_DIR="${BUILD_DIR:-${PWD}/build}"

mkdir -p "${BUILD_DIR}"

make \
    --directory="${BUILD_DIR}" \
    --file="${PWD}/Makefile" \
    LIBTRUSTEDLO_PATH="${PWD}" \
    TARGET="${TARGET}" \
    CPU="${CPU}" \
    MICROKIT_SDK="${MICROKIT_SDK}" \
    MICROKIT_BOARD="${MICROKIT_BOARD}" \
    MICROKIT_CONFIG="${MICROKIT_CONFIG}" \
    LLVM=1 \
    BUILD_DIR=.