#
# Copyright (C) 2024 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds a Rust TA with the AOSP prebuilt Rust and LLVM toolchains.
#
# Included by the Makefile of each TA, which sets UUID. That Makefile is
# invoked by vendor/optee/optee_os/mk/aosp_optee.mk (see Android.mk) with:
#   O                          output directory
#   TA_DEV_KIT_DIR             OP-TEE TA dev kit (export-ta_arm64)
#   OPTEE_CLANG_COMPILER_PATH  AOSP clang bin directory, with trailing slash
#   PYTHON3                    python used to sign the TA
# and produces $(O)/$(UUID).ta and $(O)/$(UUID).stripped.elf.
#
# The build is offline: all crates.io dependencies are patched to crates in
# the AOSP tree, see [patch.crates-io] in Cargo.toml.

ifeq ($(UUID),)
$(error UUID is not set)
endif
ifeq ($(TA_DEV_KIT_DIR),)
$(error TA_DEV_KIT_DIR is not set)
endif
ifeq ($(OPTEE_CLANG_COMPILER_PATH),)
$(error OPTEE_CLANG_COMPILER_PATH is not set)
endif

# Linker script, exported symbols and this file, shared by the TAs
TA_COMMON_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

ANDROID_ROOT ?= $(abspath $(CURDIR)/../../../../..)

# Use the same Rust version as Soong
RUST_PREBUILTS_VERSION ?= $(shell sed -n 's/^\s*RustDefaultVersion\s*=\s*"\(.*\)"/\1/p' \
	$(ANDROID_ROOT)/build/soong/rust/config/global.go)
RUST_BIN ?= $(ANDROID_ROOT)/prebuilts/rust-toolchain/linux-x86/$(RUST_PREBUILTS_VERSION)/bin

CARGO := $(RUST_BIN)/cargo
LINKER := $(OPTEE_CLANG_COMPILER_PATH)ld.lld
OBJCOPY := $(OPTEE_CLANG_COMPILER_PATH)llvm-objcopy
PYTHON3 ?= python3
SIGN := $(TA_DEV_KIT_DIR)/scripts/sign_encrypt.py
TA_SIGN_KEY ?= $(TA_DEV_KIT_DIR)/keys/default_ta.pem

# The prebuilt toolchain only ships core/alloc for bare-metal aarch64
TARGET := aarch64-unknown-none

O ?= $(CURDIR)/out
PROFILE ?= release
OUTDIR := $(O)/cargo/$(TARGET)/$(PROFILE)

# Log level from the OP-TEE TA log level of the dev kit, as for C TAs.
# OP-TEE has no warn level: level 1 (error) also keeps warnings.
CFG_TEE_TA_LOG_LEVEL ?= $(shell sed -n 's/^CFG_TEE_TA_LOG_LEVEL ?= *//p' \
	$(TA_DEV_KIT_DIR)/mk/conf.mk)
LOG_FEATURE_0 := log-off
LOG_FEATURE_1 := log-warn
LOG_FEATURE_2 := log-info
LOG_FEATURE_3 := log-debug
LOG_FEATURE_4 := log-trace
LOG_FEATURE := $(LOG_FEATURE_$(strip $(CFG_TEE_TA_LOG_LEVEL)))
ifeq ($(LOG_FEATURE),)
$(error Invalid CFG_TEE_TA_LOG_LEVEL: '$(CFG_TEE_TA_LOG_LEVEL)')
endif

CARGO_FLAGS := --features $(LOG_FEATURE)
ifneq ($(PROFILE),debug)
CARGO_FLAGS += --release
endif

TA_RUSTFLAGS := \
	-C relocation-model=pic \
	-C link-arg=-T$(TA_COMMON_DIR)/ta.aarch64.lds \
	-C link-arg=--dynamic-list=$(TA_COMMON_DIR)/ta.syms \
	-C link-arg=-e__ta_entry \
	-C link-arg=-pie \
	-C link-arg=--sort-section=alignment \
	-C link-arg=-zmax-page-size=0x1000 \
	-C link-arg=-zcommon-page-size=0x1000 \
	-L native=$(TA_DEV_KIT_DIR)/lib \
	-C link-arg=-lutee \
	-C link-arg=-lutils

# Needed by the optee-utee-sys build script
export TA_DEV_KIT_DIR
# Keep cargo away from ~/.cargo
export CARGO_HOME := $(O)/cargo-home
export CARGO_TARGET_DIR := $(O)/cargo
export RUSTC := $(RUST_BIN)/rustc
export CARGO_TARGET_AARCH64_UNKNOWN_NONE_LINKER := $(LINKER)
export CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUSTFLAGS := $(strip $(TA_RUSTFLAGS))

# Build scripts and proc-macros are built for the host. The Android build does
# not provide a host `cc` in PATH, so link them with the AOSP clang against the
# AOSP host glibc sysroot, using the same flags as Soong
# (build/soong/cc/config/x86_linux_host.go). Cargo does not apply rustflags to
# host artifacts when --target is passed, so the flags are given to clang via
# CCC_OVERRIDE_OPTIONS ('#' silences it, '+' appends an argument). The target
# linker is ld.lld, so only host links are affected.
HOST_GCC_ROOT := $(ANDROID_ROOT)/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.17-4.8
HOST_GCC_LIB := $(HOST_GCC_ROOT)/lib/gcc/x86_64-linux/4.8.3
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER := $(OPTEE_CLANG_COMPILER_PATH)clang
export CCC_OVERRIDE_OPTIONS := \# \
	+--gcc-toolchain=$(HOST_GCC_ROOT) \
	+--sysroot=$(HOST_GCC_ROOT)/sysroot \
	+-B$(HOST_GCC_LIB) \
	+-L$(HOST_GCC_LIB) \
	+-L$(HOST_GCC_ROOT)/x86_64-linux/lib64 \
	+-fuse-ld=lld

.PHONY: all ta clean debug

all: $(O)/$(UUID).ta

ta:
	$(CARGO) build --offline --locked --target $(TARGET) --no-default-features $(CARGO_FLAGS)

$(O)/$(UUID).stripped.elf: ta
	$(OBJCOPY) --strip-unneeded $(OUTDIR)/ta $@

$(O)/$(UUID).ta: $(O)/$(UUID).stripped.elf
	$(PYTHON3) $(SIGN) --uuid $(UUID) --key $(TA_SIGN_KEY) --in $< --out $@

clean:
	rm -rf $(O)

debug:
	$(MAKE) PROFILE=debug all
