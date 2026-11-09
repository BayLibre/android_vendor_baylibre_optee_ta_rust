# KeyMint TA Checklist

Copy of the TA-side sections of the porting checklists of
`system/keymint/README.md` (android-17.0.0_r1,
cfeefc94bf8c4f19d19dca193d376a1fc05e8e3e). The "HAL Service" section is tracked
in `hardware/baylibre/optee_hal_rust/keymint/Checklist.md`. Each item is ticked by the commit
that implements it.

### Rust Toolchain and Heap Allocator

Using the reference implementation requires a Rust toolchain that can target the secure environment.
This toolchain (and any associated system libraries) must also support heap allocation (or an
approximation thereof) via the [`alloc` sysroot crate](https://doc.rust-lang.org/alloc/).

If the BoringSSL-based implementation of cryptographic functionality is used (see below), then some
parts of the Rust `std` library must also be provided, in order to support the compilation of the
[`openssl`](https://docs.rs/openssl) wrapper crate.

**Checklist:**

- [x] Rust toolchain that targets secure environment.
- [x] Heap allocation support via `alloc`.

### TA Driver

The `kmr-ta` crate provides the majority of the implementation of the KeyMint TA, but needs a driver
program that:

- Performs start-of-day administration (e.g. logging setup).
- Populates initially required information (e.g. `kmr_ta::HardwareInfo`)
- Creates a `kmr_ta::KeyMintTa` instance.
- Configures the communication channel with the HAL service.
- Configures the communication channel with the bootloader, which is required so that the current
  root-of-trust boot information can be received.
- Holds the main loop that:
    - reads request messages from the channel(s)
    - passes request messages to `kmr_ta::KeyMintTa::process()`, receiving a response
    - writes response messages back to the relevant channel.

**Checklist:**

- [ ] Implementation of `main` equivalent for TA, handling scheduling of incoming requests.
- [x] Implementation of communication channel between HAL service and TA.
- [ ] Implementation of communication channel from bootloader to TA.
    - [ ] Trigger call to `kmr_ta::KeyMintTa::set_boot_info` on receipt of boot info.

The Cuttlefish implementation of the [KeyMint/Rust
TA](https://cs.android.com/android/platform/superproject/main/+/main:device/google/cuttlefish/host/commands/secure_env/rust/lib.rs)
provides an example of all of the above.

### Bootloader

The bootloader is required to transmit root of trust and boot state information to the TA at start
of day, so the TA can bind keys to the root of trust appropriately.  The bootloader should fill out
and send a `kmr_wire::SetBootInfoRequest` message to do this.  The contents of this message should
be transmitted securely, even in the presence of a subverted version of Android userspace.

**Checklist:**

- [ ] Implementation of secure communication channel from bootloader to TA.
- [ ] Trigger for and population of `kmr_wire::SetBootInfoRequest` message.

### Authenticators

KeyMint supports auth-bound keys that can only be used when an appropriate hardware authentication
token (HAT) is presented. Secure authenticators such as Gatekeeper or Fingerprint produce these
HATs, and validation of them requires that:

- [ ] KeyMint and the authenticators share a common monotonic time source.
- [ ] The authenticators have access to the (per-boot) HMAC signing key, via one of:
   - [ ] The authenticator retrieves the HMAC key from KeyMint via a communication mechanism that is
         completely internal to the secure environment, using `KeyMintTa::get_hmac_key`, or
   - [ ] The authenticator also implements the `ISharedSecret` HAL, and joins in the HMAC key
         derivation process.  This requires that the authenticator have access to the pre-shared key
         that is used as the basis of the derivation process.

### Cryptographic Abstractions

The KeyMint TA requires implementations for low-level cryptographic primitives to be provided, in
the form of implementations of the various Rust traits held in
[`kmr_common::crypto`](common/src/crypto/traits.rs).

Note that some of these traits include methods that have default implementations, which means that
an external implementation is not required (but can be provided if desired).

**Checklist:**

- [x] RNG implementation: `Rng`.
- [x] Constant time comparison implementation: `ConstTimeEq`.
- [x] AES implementation: `Aes`.
- [x] 3-DES implementation: `Des`.
- [x] HMAC implementation: `Hmac`.
- [x] RSA implementation: `Rsa`.
- [x] EC implementation, including curve 25519 support: `Ec`.
- [x] AES-CMAC or CKDF implementation: `AesCmac`, `Ckdf`.

BoringSSL-based implementations are available for all of the above.

### Device Abstractions

The KeyMint TA requires implementations of traits that involve interaction with device-specific
features or provisioned information, in the form of implementations of the various Rust traits held
(mostly) in [`kmr_ta::device`](ta/src/device.rs).

Provisioned information should be stored securely, in a manner that is resistant to reading or
writing from Android userspace.

**Checklist:**

- [x] Secure time implementation (monotonic, shared with authenticators): `kmr_common::crypto::MonotonicClock`.
- [ ] Root key(s) retrieval implementation: `RetrieveKeyMaterial`.
- [ ] Attestation key / chain retrieval implementation (optional): `RetrieveCertSigningInfo`.
- [ ] Attestation device ID retrieval implementation: `RetrieveAttestationIds`.
- [ ] Retrieval of BCC and DICE artefacts: `RetrieveRpcArtifacts`.
- [ ] Secure secret storage (for rollback-resistant keys) implementation (optional): `SecureDeletionSecretManager`.
- [ ] Bootloader status retrieval (optional): `BootloaderStatus`.
- [ ] Storage key wrapping integration (optional): `StorageKeyWrapper`.
- [ ] Trusted user presence indication (optional): `TrustedUserPresence`.
- [ ] Legacy keyblob format converter (optional): `LegacyKeyHandler`.
