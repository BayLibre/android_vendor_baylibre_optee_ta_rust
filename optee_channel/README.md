# OP-TEE channel for the Rust security HALs and TAs

This directory holds the code shared by the Rust Gatekeeper and KeyMint
implementations to talk to OP-TEE.

Google's Rust reference implementations (`system/keymint`,
`system/gatekeeper/rust`) split each service into a HAL crate (`kmr-hal`,
`gk-hal`) and a TA crate (`kmr-ta`, `gk-ta`), which exchange CBOR messages
(`kmr-wire`, `gk-wire`). The HAL crates send them through a
`SerializedChannel` trait that the device must implement. On this device,
that channel goes through OP-TEE's GlobalPlatform TEE Client API.

## Contents

| Path | Kind | Used by |
|------|------|---------|
| `libteec_bindgen.h`, `optee_bindings.rs` | `libtee_client_api_bindgen`, `libtee_optee_bindings` | HAL side |

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
