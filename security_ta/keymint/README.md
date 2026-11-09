# KeyMint reference implementation for OP-TEE

This directory holds a reference Rust KeyMint implementation for OP-TEE using
the [Apache Teaclave TrustZone SDK](https://github.com/apache/incubator-teaclave-trustzone-sdk).

It is the OP-TEE driver for Google's KeyMint Rust reference implementation
(`system/keymint`, see its `README.md`). The `kmr-ta` crate holds the KeyMint
logic. This TA provides the OP-TEE entry points, the HAL <-> TA channel and the
device-specific trait implementations required by `kmr-ta`.

`Checklist.md` tracks the TA-side items of the porting checklists of
`system/keymint/README.md`.

- **UUID**: `dba51a17-0563-11e7-93b1-6fa7b0071a51`
- **KeyMint version**: 4 (`HardwareInfo::version_number`)
- **Security level**: `TrustedEnvironment`
- **RPC**: `RpcInfo::V3`
- **HAL**: `hardware/baylibre/optee_hal_rust/keymint`
  (`android.hardware.security.keymint-service.optee.rust`)

## Origin

The TA is based on the AOSP OP-TEE KeyMint TA, by Sami Tolvanen
(https://android.googlesource.com/tee/optee/ta/keymint, revision `ffced1f`).
The TA configuration, linker script, crypto traits, key derivation, secure
deletion secrets and `GET_AUTH_TOKEN_KEY` come from it. It is reworked to build
offline in the AOSP tree with the prebuilt toolchains, to work with the HALs of
`hardware/baylibre/optee_hal_rust`, and to fix the issues found by VTS.

## Source Layout

| File | Description |
|------|-------------|
| `src/main.rs` | TA entry points, `KeyMintTa` singleton, command dispatch |
| `src/command.rs` | Command IDs |
| `src/config.rs` | TA header and properties (UUID, flags, stack/heap size) |
| `src/crypto/` | `kmr_common::crypto` trait implementations on top of the GP TEE Internal Core API |
| `src/keys.rs` | Root keys, derived from the hardware unique key |
| `src/rpc.rs` | RKP artefacts (see [Limitations](#limitations)) |
| `src/storage/sdsm.rs` | Secure deletion secret manager (rollback-resistant keys) |
| `src/storage/attest_ids.rs` | Attestation IDs, provisioned once |
| `src/error.rs` | OP-TEE to KeyMint error mapping |
| `src/ta.aarch64.lds`, `src/ta.syms` | Linker script and exported symbols |
| `Makefile` | cargo build, strip and signature (see [Build](#build)) |
| `Android.mk` | AOSP module of the signed TA |
| `Checklist.md` | TA-side checklists of `system/keymint/README.md` |

Shared with the Gatekeeper TA:

| Path | Description |
|------|-------------|
| `../rust/stubs.rs` | Symbols expected by the Rust runtime in a `no_std` TA (`getauxval`, `bcmp`, unwinding stubs) |
| `../rust/const-oid` | `const-oid` 0.9 shim over AOSP's `const-oid` 0.10 (see [Crates](#crates)) |
| `../../optee_channel/optee-ipc-ta` | System PTA calls (key derivation, RNG entropy) |
| `../../optee_channel/optee-logger-ta` | `log` backend printing through the OP-TEE trace API |

## TA Configuration

Defined in `src/config.rs`:

- **Flags**: `SINGLE_INSTANCE | MULTI_SESSION | INSTANCE_KEEP_ALIVE`. A single
  `KeyMintTa` instance is shared by the HAL session and the Gatekeeper TA
  session, and stays loaded so its in-memory state (boot info, shared secret,
  DICE artefacts) survives session close.
- **Stack**: 128 KB
- **Heap**: 3 MB

OP-TEE runs TA entry points sequentially, even across sessions, so the global
`KeyMintTa` is kept in a `spin::Once<Mutex<_>>` behind a `Send` wrapper.

`KeyMintTa` is created with `new_allowing_versions()` and accepts the V4 and V5
HAL versions, as the Trusty KeyMint TA does. The HAL only implements V4, and
ML-DSA (V5) is not supported (`NoOpMlDsa`).

## Commands

| Command | ID | Caller | Parameters |
|---------|----|--------|------------|
| `WRITE` | 1024 | HAL | param[0] MEMREF_INPUT: serialized request (max 4096 bytes) |
| `READ` | 1025 | HAL | param[0] MEMREF_OUTPUT: next response chunk |
| `SET_ATTESTATION_IDS` | 0x10001 | Provisioning tool | param[0] MEMREF_INPUT: CBOR `SetAttestationIdsRequest`. `ACCESS_CONFLICT` if already provisioned |

### HAL <-> TA Protocol

The HAL sends a CBOR-encoded `kmr-wire` request with `WRITE`. The TA calls
`KeyMintTa::process()` immediately and splits the response into chunks of at
most 4000 bytes (`kmr_ta::split_rsp`), stored in the session context. The HAL
then issues `READ` until all chunks are consumed. A new `WRITE` returns
`TEE_ERROR_BUSY` while a response is pending. A `READ` with nothing pending
returns `TEE_ERROR_NO_DATA`.

The HAL side of this protocol is `OpteeChannel::execute()`, see
`vendor/baylibre/optee_ta_rust/optee_channel/README.md`.

## Device-Specific Implementations

### Cryptographic Abstractions

All `kmr_common::crypto` traits are implemented with OP-TEE's GP TEE Internal
Core API (`optee-utee`), no BoringSSL:

| Trait | Implementation |
|-------|----------------|
| `Rng` | `TEE_GenerateRandom`. `add_entropy` forwards to the system PTA (`PTA_SYSTEM_ADD_RNG_ENTROPY`) |
| `ConstTimeEq` | `TEE_MemCompare` (constant time in OP-TEE) |
| `MonotonicClock` | `TEE_GetSystemTime`. The TA refuses to start if `gpd.tee.systemTime.protectionLevel` is below 1000 |
| `Aes` | ECB, CBC, CTR, GCM |
| `Des` | 3DES ECB, CBC |
| `Hmac`, `Hkdf` | HMAC with MD5, SHA-1, SHA-224/256/384/512 |
| `AesCmac` / `Ckdf` | AES-CMAC |
| `Rsa` | Key generation, signing, decryption |
| `Ec` | NIST P-224/256/384/521, Ed25519, X25519 (key encoding via the `sec1`/`pkcs8` crates, Ed25519 signing and public key recomputation via `ed25519-dalek`, X25519 public key recomputation via `x25519-dalek`). ECDH peer points are checked to be on the curve with the GP arithmetic API (`crypto/nist_point.rs`) |
| `Sha256` | SHA-256 |
| `MlDsa` | Not supported (`NoOpMlDsa`) |

### Device Abstractions

| Trait (`kmr_ta::device`) | Implementation |
|--------------------------|----------------|
| `RetrieveKeyMaterial` | Root KEK and KAK derived from the hardware unique key via `PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY` (`src/keys.rs`). The agreed HMAC key is kept by kmr-ta |
| `RetrieveCertSigningInfo` | Not provided: attestation needs an attestation key from the caller (RKP), otherwise it fails with `ATTESTATION_KEYS_NOT_PROVISIONED` |
| `RetrieveAttestationIds` | OP-TEE secure storage (`TEE_STORAGE_PRIVATE_REE`), object `AttestationIds_1`, see [Attestation IDs](#attestation-ids) |
| `RetrieveRpcArtifacts` | HBK derived from the hardware unique key. No DICE chain, so RKP is not available (`src/rpc.rs`) |
| `SecureDeletionSecretManager` | OP-TEE secure storage (`TEE_STORAGE_PRIVATE_REE`), object `SecureDeletionSecrets_1` |
| `BootloaderStatus` | `BootloaderDone` |
| `StorageKeyWrapper` | Not provided |
| `TrustedUserPresence` | Unsupported |
| `LegacyKeyHandler` | Not provided |

The REE FS behind `TEE_STORAGE_PRIVATE_REE` is handled by `tee-supplicant`.

A factory reset does not wipe the full TA secure storage:

1. It formats `/data`, `/cache` and `/metadata`.
2. The keys are destroyed through `deleteAllKeys`, called:
   1. by `RecoverySystemService` before rebooting to recovery;
   2. by vold on the first boot after the reset, when
      `ro.crypto.metadata_init_delete_all_keys.enabled` is set.
3. `deleteAllKeys` deletes `SecureDeletionSecrets_1` from the secure storage
   (`/mnt/vendor/persist/tee`), so every existing key blob becomes unusable.

### Attestation IDs

The attestation IDs are provisioned once per device by
`keymint-optee-provision-ids` (`hardware/baylibre/optee_hal_rust/keymint/provisioning`) with
`SET_ATTESTATION_IDS`. The TA stores the CBOR-encoded `AttestationIdInfo` in
`AttestationIds_1`, created without `TEE_DATA_FLAG_OVERWRITE`, so any later
provisioning fails. `kmr-ta` ignores `SetAttestationIds` requests from the
HAL, and only logs an error.

Until provisioning, `RetrieveAttestationIds::get_ids()` returns `None`: ID
attestation fails with `CANNOT_ATTEST_IDS`, and the RKP `DeviceInfo` cannot be
built. The TA remembers that the IDs are missing until `SET_ATTESTATION_IDS`,
so that key generation does not read the secure storage each time.
`destroyAttestationIds` returns `UNIMPLEMENTED`, as the KeyMint AIDL requires
for this deprecated method. To provision the IDs again on a development
device, erase the TA secure storage (`/mnt/vendor/persist/tee`) and `/data`.
`deleteAllKeys` does not delete `AttestationIds_1`, so the IDs survive a
factory reset.

## Build

The TA is built by `vendor/optee/optee_os/mk/aosp_optee.mk`, included from
`Android.mk` through `BUILD_OPTEE_MK` (set in
`device/epam/aosp-xenvm-trout/optee/optee.mk`). It builds the OP-TEE TA dev
kit, then calls this `Makefile`, which:

1. Builds the TA with the AOSP prebuilt Rust toolchain, the same version as
   Soong (`RustDefaultVersion`), for `aarch64-unknown-none` (the prebuilt only
   ships `core`/`alloc` for bare-metal aarch64), linking with the AOSP clang
   `ld.lld`. Build scripts and proc macros are linked for the host with the
   AOSP clang and the prebuilt host glibc sysroot.
2. Strips the ELF with `llvm-objcopy` and signs it with the dev kit
   `sign_encrypt.py`.

```bash
m dba51a17-0563-11e7-93b1-6fa7b0071a51.ta
```

Output: `$ANDROID_PRODUCT_OUT/vendor/lib/optee_armtz/dba51a17-0563-11e7-93b1-6fa7b0071a51.ta`
(the unsigned ELF is copied to `$ANDROID_PRODUCT_OUT/unsigned/`).

The `Makefile` can also be called directly, for instance for quicker
iterations:

```bash
make -C vendor/baylibre/optee_ta_rust/security_ta/keymint \
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
`$ANDROID_PRODUCT_OUT/optee/ta/dba51a17-0563-11e7-93b1-6fa7b0071a51.ta` to force a rebuild.

### Crates

The build is offline (`cargo build --offline --locked`): every crates.io
dependency is redirected to the AOSP tree through `[patch.crates-io]` in
`Cargo.toml`, and `Cargo.lock` pins the result:

| Crates | Location |
|--------|----------|
| `kmr-common`, `kmr-derive`, `kmr-ta`, `kmr-wire` | `system/keymint` |
| `optee-utee`, `optee-utee-sys` | `external/rust/teaclave-trustzone-sdk` (BayLibre fork, ported to the crate versions of the AOSP tree) |
| Third-party crates vendored by AOSP | `external/rust/android-crates-io/crates` (and `extra_versions` for `rand_core`) |
| Third-party crates not in AOSP (`ed25519-dalek`, `x25519-dalek`, `sha2`, ...) | `external/rust/crates/<crate>`: crates.io release archives, one BayLibre repository per crate |
| `const-oid` 0.9 | `../rust/const-oid` |

`der` 0.7, `spki` 0.7 and `x509-cert` 0.2 require `const-oid` ^0.9 while AOSP
only vendors 0.10. Soong ignores semver and builds them against the 0.10
sources. cargo cannot `[patch]` a ^0.9 requirement with a 0.10 crate, so
`../rust/const-oid` is a 0.9.6 crate that re-exports the AOSP 0.10 sources
unchanged.

## Limitations

1. **Secure deletion**: the secrets are stored in REE FS, so root in Android
   can restore an older `SecureDeletionSecrets_1` and recover deleted keys.
   Rollback resistance needs RPMB backed storage.
2. **Attestation IDs**: stored in REE FS, so root in Android can delete the
   file and provision new IDs. They need RPMB backed storage. Any client of
   the TA can provision a device that has no IDs yet.
3. **Attestation**: there is no factory attestation key
   (`RetrieveCertSigningInfo`), so the device is RKP-only, and no DICE chain
   until the DICE PTA is available, so RKP cannot provision it:
   `generateCertificateRequest` fails, and `fused` is `false`. Key
   attestation then works only with an attestation key provided by the
   caller, and fails with `ATTESTATION_KEYS_NOT_PROVISIONED` otherwise.
   VTS provides its own attestation keys, so in
   `VtsAidlKeyMintTargetTest` only `AttestKeyTest.RsaAttestedAttestKeys`
   is skipped ("RKP-only devices do not have a factory key"). In
   `VtsHalRemotelyProvisionedComponentTargetTest`, the
   `CertificateRequestV2Test` tests `EmptyRequest`, `NonEmptyRequest`,
   `NonEmptyRequestMultipleKeys`, `NonEmptyRequestReproducible` and
   `DeviceInfo` fail.
4. **Root of Trust**: nothing sends the boot info yet. kmr-ta expects it from
   the bootloader through a channel that Android cannot subvert, which this
   device does not provide, so it fails every key operation with
   `HARDWARE_NOT_YET_AVAILABLE`.
5. **NIST key import**: a P-224/256/384/521 private key without its
   optional public key (RFC 5915) is rejected with `INVALID_ARGUMENT`, as
   the GP API cannot compute the public key.
6. **Signing key**: the TA is signed with the OP-TEE default development key.
   Production devices need their own `TA_SIGN_KEY`.
