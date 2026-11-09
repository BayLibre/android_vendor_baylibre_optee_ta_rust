# Gatekeeper TA Checklist

Copy of the TA-side sections of the porting checklists of
`system/gatekeeper/rust/README.md` (android-17.0.0_r1,
5b5e75b5bda9fccbc3132e9624cb25286babdaac). The "HAL Service" section is
tracked in `hardware/baylibre/optee_hal_rust/gatekeeper/Checklist.md`. Each item is ticked by
the commit that implements it.

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

The `gk-ta` crate provides the majority of the implementation of the Gatekeeper TA, but needs a
driver program that:

- Performs start-of-day administration (e.g. logging setup).
- Creates a `gk_ta::GatekeeperTa` instance.
- Configures the communication channel with the HAL service.
- Provides a mechanism for obtaining the shared HMAC key used for authentication.
- Holds the main loop that:
    - reads request messages from the channel(s)
    - passes request messages to `gk_ta::GatekeeperTa::process()`, receiving a response
    - writes response messages back to the relevant channel.

**Checklist:**

- [x] Implementation of `main` equivalent for TA, handling scheduling of incoming requests.
- [x] Implementation of communication channel between HAL service and TA.
- [x] Implementation of mechanism to retrieve HMAC key (see next section).
  (from the KeyMint TA, first way of the next section: `src/crypto/authkey.rs`)

The <a
href="https://android.googlesource.com/trusty/app/gatekeeper/+/refs/heads/main/rust/">Trusty-specific
implementation</a> provides an example of this.

### Auth Key Retrieval

Gatekeeper signs its authentication tokens with a per-boot HMAC key, which can be obtained in one of
the following ways:

- The Gatekeeper TA can directly retrieve the auth token key from another component (typically
  KeyMint) in the secure environment.  In this case, the device-specific implementation of the
  `AuthKeyManagement` trait performs signing operations using the retrieved key.
- The Gatekeeper TA can implement the `ISharedSecret` HAL and take part in the negotiation of the
  HMAC key. The common code includes an implementation of the `AuthKeyManagement` trait that handles
  this scenario, but the device must provide implementations of the following traits:
  - [ ] CDKF key derivation operation: `SharedSecretDerive`
  - [ ] Mechanism to retrieve a pre-shared key: `RetrievePresharedKey`

### Device-Specific Abstractions

The Gatekeeper TA requires implementations for low-level primitives to be provided, in the form of
implementations of the various Rust traits held in [`gk_ta::traits`](ta/src/traits.rs).

Note that some of these traits include methods that have default implementations, which means that
an external implementation is not required (but can be provided if desired).

**Checklist:**

- [x] RNG implementation: `Rng`.
- [x] Constant time comparison implementation: `ConstTimeEq`.
- [x] Secure time implementation (monotonic, shared with authenticators): `MonotonicClock`.
- [x] Implementation of mechanism to retrieve password key: `PasswordKeyRetrieval`
- [x] Persistent secure storage of failure records: `FailureRecording`
   - [x] The TA code includes one implementation of the `FailureRecording` trait, based on an
         implementation of a trait for accessing files in a secure filesystem: `SecureFilesystem`

BoringSSL-based implementations are available for some of the above, in the `boringssl/` directory.
