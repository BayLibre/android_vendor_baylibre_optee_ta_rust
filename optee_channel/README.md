# OP-TEE channel for the Rust security HALs and TAs

This directory holds the code shared by the Rust Gatekeeper and KeyMint
implementations to talk to OP-TEE.

Google's Rust reference implementations (`system/keymint`,
`system/gatekeeper/rust`) split each service into a HAL crate (`kmr-hal`,
`gk-hal`) and a TA crate (`kmr-ta`, `gk-ta`), which exchange CBOR messages
(`kmr-wire`, `gk-wire`). The HAL crates send them through a
`SerializedChannel` trait that the device must implement. On this device,
that channel goes through OP-TEE's GlobalPlatform TEE Client API.

```
HAL (hardware/baylibre/optee_hal_rust)
    |
libtee_optee_channel  -- OpteeChannel
libtee_optee_bindings -- libteec FFI
    |
libteec → /dev/tee0 → SMC → OP-TEE OS
```

## Contents

| Path | Kind | Used by |
|------|------|---------|
| `libteec_bindgen.h`, `optee_bindings.rs` | `libtee_client_api_bindgen`, `libtee_optee_bindings` | HAL side |
| `optee_channel.rs` | `libtee_optee_channel` | Gatekeeper and KeyMint HALs |

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
| Max response (TA) | n/a | 4000 per chunk, signal byte included (`KEYMINT_MAX_MESSAGE_CONTENT_SIZE`) |
