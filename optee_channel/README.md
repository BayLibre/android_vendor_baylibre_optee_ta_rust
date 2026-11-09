# OP-TEE channel for the Rust security HALs and TAs

This directory holds the code shared by the Rust Gatekeeper and KeyMint
implementations to talk to and from OP-TEE:

- on the normal world side, the libteec bindings and the HAL <-> TA channel used
  by the HALs in `hardware/baylibre/optee_hal_rust/{gatekeeper,keymint}`;
- on the secure world side, two `no_std` crates used by the TAs in
  `vendor/baylibre/optee_ta_rust/security_ta/{gatekeeper,keymint}`.

Google's Rust reference implementations (`system/keymint`,
`system/gatekeeper/rust`) split each service into a HAL crate (`kmr-hal`,
`gk-hal`) and a TA crate (`kmr-ta`, `gk-ta`), which exchange CBOR messages
(`kmr-wire`, `gk-wire`). The HAL crates send them through a
`SerializedChannel` trait that the device must implement. On this device,
that channel goes through OP-TEE's GlobalPlatform TEE Client API.

```
HAL (hardware/baylibre/optee_hal_rust)      TA (vendor/baylibre/optee_ta_rust/security_ta)
    |                                         |
libtee_optee_channel  -- OpteeChannel         optee-logger-ta  -- log backend
libtee_optee_bindings -- libteec FFI          optee-ipc-ta     -- TA-to-TA / PTA calls
    |                                         |
libteec → /dev/tee0 → SMC →  OP-TEE mediator (EL2) →  OP-TEE OS
```

## Contents

| Path | Kind | Used by |
|------|------|---------|
| `libteec_bindgen.h`, `optee_bindings.rs` | `libtee_client_api_bindgen`, `libtee_optee_bindings` | HAL side |
| `optee_channel.rs` | `libtee_optee_channel` | Gatekeeper and KeyMint HALs |
| `optee-ipc-ta/` | cargo crate, `no_std` | Gatekeeper and KeyMint TAs |
| `optee-logger-ta/` | cargo crate, `no_std` | Gatekeeper and KeyMint TAs |

## Normal World

### libteec Bindings

Rust bindings of the GlobalPlatform TEE Client API, linked against `libteec` from
`vendor/optee/optee_client`.

The types, constants and functions are generated at build time by bindgen from
`tee_client_api.h`, the header exported by `libteec`, so their layouts always
match the `libteec` in the tree. `libtee_optee_bindings` re-exports them
and adds:
- `param_types()`: `TEEC_PARAM_TYPES()`, a function-like macro that bindgen
  does not translate;
- `uuid_from_str()`: parses a TA UUID string into a `TEEC_UUID`.

### HAL <-> TA Channel (`optee_channel.rs`)

`OpteeChannel::new(uuid)` opens a TEE context and a session to the TA. The HAL
keeps this single session for its whole lifetime. The session and context are
closed on drop.

Each HAL wraps `OpteeChannel` in a local newtype implementing the
`SerializedChannel` trait of its HAL library (`gk_hal` or `kmr_hal`): the trait
and the type are both foreign to the HAL crate, so the orphan rule requires the
implementation to live there. The HAL also sets `SerializedChannel::MAX_SIZE`
and picks one of the two execution modes below.

Requests and responses are opaque byte buffers for the channel: the CBOR
encoding (`gk-wire`, `kmr-wire`) is handled by the HAL and TA libraries.

#### Single Invoke: `execute_single()` (Gatekeeper)

One `TEEC_InvokeCommand` per request:

| Command | ID | param[0] | param[1] |
|---------|----|----------|----------|
| `PROCESS` | 1026 | MEMREF_TEMP_INPUT: request | MEMREF_TEMP_OUTPUT: response (4096-byte buffer) |

The response size is read back from param[1]. A response larger than the
buffer is reported as an error.

#### Split Write/Read: `execute()` (KeyMint)

KeyMint responses can be larger than a single shared memory buffer, so the
request and the response are carried by separate commands:

| Command | ID | param[0] |
|---------|----|----------|
| `WRITE` | 1024 | MEMREF_TEMP_INPUT: request |
| `READ` | 1025 | MEMREF_TEMP_OUTPUT: one response chunk (4096-byte buffer) |

1. `WRITE` sends the whole request. The TA processes it and queues the response
   chunks.
2. `READ` is called until the end of the response. Each chunk starts with a
   signal byte, `1` if more chunks follow and `0` for the last one, followed by
   the chunk data. `TEEC_ERROR_NO_DATA` also ends the response.
3. The chunk data are concatenated into the response.

#### Input Only: `invoke_with_input()`

Invokes any command with a single MEMREF_TEMP_INPUT in param[0] and no output,
and returns the TEEC result code on failure. Used by
`keymint-optee-provision-ids` for `SET_ATTESTATION_IDS` (0x10001).

#### Error Handling

Errors are returned to the HAL, which turns them into a binder
`TRANSACTION_FAILED` exception.

There is no reconnect on `TEEC_ERROR_TARGET_DEAD` (the TA panicked or was
unloaded). A dead TA lost its state, such as the KeyMint HAL info and shared
secret, which a new session can't restore. Every later call fails, until the
device reboots.

### Size Constraints

The sizes on both sides must stay consistent:

| | Gatekeeper | KeyMint |
|-|------------|---------|
| Max request (HAL `MAX_SIZE`) | 8000 | 4000 |
| Max request (TA) | 8000 (`GK_MAX_BUFFER_LENGTH`) | 4096 (`KEYMINT_MAX_BUFFER_LENGTH`) |
| Response buffer (channel) | 4096 (`GK_RESPONSE_MAX`) | 4096 per chunk (`CMD_READ_CHUNK_SIZE`) |
| Max response (TA) | 4096 (`GK_MAX_MESSAGE_CONTENT_SIZE`) | 4000 per chunk, signal byte included (`KEYMINT_MAX_MESSAGE_CONTENT_SIZE`) |

## Secure World

Both crates are pulled by the TAs through a `path` dependency in their
`Cargo.toml` and build against the Teaclave TrustZone SDK

### `optee-ipc-ta`

Thin wrapper around the TA-to-TA syscalls of the GP TEE Internal Core API
(`TEE_OpenTASession`, `TEE_InvokeTACommand`, `TEE_CloseTASession`):
- `open(uuid, params)` returns a `Session`, closed on drop;
- `Session::invoke(command, params)`;
- `Param` / `Params`: memref (input, output, inout), value and none parameters,
  built from Rust slices;
- the OP-TEE system PTA UUID and commands used by the TAs
  (`PTA_SYSTEM_ADD_RNG_ENTROPY`, `PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY`), and
  `add_rng_entropy()` and `derive_ta_unique_key()`, which call them.

### `optee-logger-ta`

A `log` crate backend printing through OP-TEE's `trace_ext_puts()`, so TA logs
end up on the OP-TEE console, prefixed with `TA_RUST_<LEVEL>`. Messages are
truncated to 511 bytes. The maximum level is set at init; the TAs choose it at
build time with their `log-*` cargo features, selected by their Makefile from
`CFG_TEE_TA_LOG_LEVEL`.
