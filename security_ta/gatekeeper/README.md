# Gatekeeper reference implementation for OP-TEE

This directory holds a reference Rust Gatekeeper implementation for OP-TEE
using the [Apache Teaclave TrustZone SDK](https://github.com/apache/incubator-teaclave-trustzone-sdk).

It is the OP-TEE driver for Google's Gatekeeper Rust reference implementation
(`system/gatekeeper/rust`, see its `README.md`). The `gk-ta` crate holds the
Gatekeeper logic (enroll, verify, throttling, auth token generation). This TA
provides the OP-TEE entry points, the HAL <-> TA channel and the
device-specific trait implementations required by `gk-ta`.

`Checklist.md` tracks the TA-side items of the porting checklists of
`system/gatekeeper/rust/README.md`.

- **UUID**: `4d573443-6a56-4272-ac6f-2425af9ef9bb`
- **HAL**: `hardware/baylibre/optee_hal_rust/gatekeeper`
  (`android.hardware.gatekeeper-service.optee.rust`)

## Origin

The TA configuration, linker script, `ConstTimeEq` and `MonotonicClock` come
from the AOSP OP-TEE KeyMint TA, by Sami Tolvanen
(https://android.googlesource.com/tee/optee/ta/keymint, revision `ffced1f`),
like the KeyMint TA.

## Source Layout

| File | Description |
|------|-------------|
| `src/main.rs` | TA entry points, `PROCESS` command handler |
| `src/command.rs` | Command IDs |
| `src/config.rs` | TA header and properties (UUID, flags, stack/heap size), through `ta_config!` |
| `Makefile` | Sets the TA UUID and includes `../common/ta.mk` (see [Build](#build)) |
| `Android.mk` | AOSP module of the signed TA |
| `Checklist.md` | TA-side checklists of `system/gatekeeper/rust/README.md` |

Shared with the KeyMint TA:

| Path | Description |
|------|-------------|
| `../common/stubs.rs` | Symbols expected by the Rust runtime in a `no_std` TA (`getauxval`, `bcmp`, unwinding stubs) |
| `../common/src/lib.rs` | `optee-ta-common`: TA UUIDs, `ta_config!` (TA header, properties, heap and trace symbols), system time, and parameter helpers (`read_input`, `check_output`, `write_output`) |
| `../common/ta.mk` | Build rules shared by the TAs: cargo build, strip and signature |
| `../common/ta.aarch64.lds`, `../common/ta.syms` | Linker script and exported symbols, shared by the TAs |
| `../../optee_channel/optee-logger-ta` | `log` backend printing through the OP-TEE trace API |

## TA Configuration

Defined in `src/config.rs`:

- **Flags**: `SINGLE_INSTANCE | MULTI_SESSION`, same as the C TA.
  `INSTANCE_KEEP_ALIVE` is intentionally not set.
- **Stack**: 64 KB (C TA: 16 KB)
- **Heap**: 512 KB (C TA: 32 KB)

## Commands

| Command | ID | Parameters |
|---------|----|------------|
| `PROCESS` | 1026 | param[0] MEMREF_INPUT: serialized request (max 8000 bytes)<br>param[1] MEMREF_OUTPUT: serialized response |

Each `PROCESS` call is self-contained: the request (`gk-wire`, CBOR) is read
from param[0] and the response is written to param[1]. The TA returns
`TEE_ERROR_OVERFLOW` if the request exceeds `GK_MAX_BUFFER_LENGTH` and
`TEE_ERROR_SHORT_BUFFER` if the output buffer is too small.

Until the device-specific traits are implemented, the TA answers every
request with a general failure.

`GK_MAX_BUFFER_LENGTH` (`src/main.rs`) must match `SerializedChannel::MAX_SIZE`
in the HAL (`hardware/baylibre/optee_hal_rust/gatekeeper/src/gatekeeper_hal_main.rs`).

The legacy C TA commands (`GK_ENROLL=0`, `GK_VERIFY=1`, ...) are not
supported.

The HAL side of this protocol is `OpteeChannel::execute_single()`, see
`vendor/baylibre/optee_ta_rust/optee_channel/README.md`.

## Build

The TA is built by `vendor/optee/optee_os/mk/aosp_optee.mk`, included from
`Android.mk` through `BUILD_OPTEE_MK` (set in
`device/epam/aosp-xenvm-trout/optee/optee.mk`). It builds the OP-TEE TA dev
kit, then calls this `Makefile`, which includes `../common/ta.mk`, shared
with the other TA. It:

1. Builds the TA with the AOSP prebuilt Rust toolchain, the same version as
   Soong (`RustDefaultVersion`), for `aarch64-unknown-none` (the prebuilt only
   ships `core`/`alloc` for bare-metal aarch64), linking with the AOSP clang
   `ld.lld`.
2. Strips the ELF with `llvm-objcopy` and signs it with the dev kit
   `sign_encrypt.py`.

```bash
m 4d573443-6a56-4272-ac6f-2425af9ef9bb.ta
```

Output: `$ANDROID_PRODUCT_OUT/vendor/lib/optee_armtz/4d573443-6a56-4272-ac6f-2425af9ef9bb.ta`
(the unsigned ELF is copied to `$ANDROID_PRODUCT_OUT/unsigned/`).

The `Makefile` can also be called directly, for instance for quicker
iterations:

```bash
make -C vendor/baylibre/optee_ta_rust/security_ta/gatekeeper \
     TA_DEV_KIT_DIR=$ANDROID_PRODUCT_OUT/optee/arm-plat-rcar_gen5/export-ta_arm64 \
     OPTEE_CLANG_COMPILER_PATH=$ANDROID_BUILD_TOP/prebuilts/clang/host/linux-x86/<clang version>/bin/
```

Variables:
- `TA_DEV_KIT_DIR`, `OPTEE_CLANG_COMPILER_PATH` (with trailing slash): required
- `O`: output directory (default: `out/`)
- `CFG_TEE_TA_LOG_LEVEL`: TA log level (default: the dev kit value, as for C
  TAs). 0: off, 1: errors and warnings, 2: info, 3: debug, 4: trace. OP-TEE
  prints TA logs only if built with `CFG_TEE_CORE_TA_TRACE=y`.
- `TA_SIGN_KEY`: TA signing key (default:
  `$(TA_DEV_KIT_DIR)/keys/default_ta.pem`)
- `make debug`: Cargo `dev` profile (`opt-level = 0`, debug info, integer
  overflow checks and `debug_assert!`). Use it only to chase a TA bug: the TA
  is bigger and slower, the software crypto in particular, and uses more
  stack, so its VTS results do not represent the release TA. The installed
  `.ta` is stripped either way; the debug info stays in
  `$(O)/cargo/aarch64-unknown-none/debug/ta`, to symbolize TA aborts with
  `addr2line` or `gdb`.

From the AOSP build, extra variables can be passed with `OPTEE_EXTRA_TA_FLAGS`
in `optee.mk`, e.g. `OPTEE_EXTRA_TA_FLAGS += PROFILE=debug` for the debug
profile. They apply to every TA built by `aosp_optee.mk`. The TA rebuild rule
does not depend on them: delete
`$ANDROID_PRODUCT_OUT/optee/ta/4d573443-6a56-4272-ac6f-2425af9ef9bb.ta` to force a rebuild.

### Crates

The build is offline (`cargo build --offline --locked`): every crates.io
dependency is redirected to the AOSP tree through `[patch.crates-io]` in
`Cargo.toml`, and `Cargo.lock` pins the result:

| Crates | Location |
|--------|----------|
| `gk-ta`, `gk-wire` | `system/gatekeeper/rust` |
| `hal-wire`, `hal-wire-derive` | `system/security/hals` |
| `optee-utee`, `optee-utee-sys` | `external/rust/teaclave-trustzone-sdk` (BayLibre fork, ported to the crate versions of the AOSP tree) |
| Third-party crates vendored by AOSP | `external/rust/android-crates-io/crates` |
| `crunchy`, `libc_alloc`, `rustc_version` (not in AOSP) | `external/rust/crates/<crate>`: crates.io release archives, one BayLibre repository per crate |

## Limitations

1. **Signing key**: the TA is signed with the OP-TEE default development key.
   Production devices need their own `TA_SIGN_KEY`.
