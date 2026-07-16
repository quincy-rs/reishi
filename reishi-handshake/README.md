# reishi-handshake

[![Crates.io](https://img.shields.io/crates/v/reishi-handshake.svg)](https://crates.io/crates/reishi-handshake)
[![Documentation](https://docs.rs/reishi-handshake/badge.svg)](https://docs.rs/reishi-handshake/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

Pure, sans-IO implementation of the [Noise Protocol](https://noiseprotocol.org/noise.html) IK handshake with optional KEM-only and hybrid post-quantum modes.

## The IK pattern

IK is a one round-trip, mutually authenticated Noise handshake where the initiator already knows the responder's static public key:

```
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

The initiator sends a single message containing its ephemeral key, performs DH against the responder's static key (`es`), sends its own static key (now encrypted), and performs a second DH (`ss`). The responder replies with its ephemeral key and completes the remaining DH operations (`ee`, `se`).

This is a good fit for VPN/QUIC because the client always knows the server's public key ahead of time, the 1-RTT exchange maps directly to QUIC's handshake model, and both sides are authenticated from the first flight, preventing unauthenticated resource exhaustion.

## Ciphersuite

Reishi uses a single fixed ciphersuite with no negotiation:

```
Noise_IK_25519_ChaChaPoly_BLAKE2s
```

**X25519** is the obvious choice for DH. It's constant-time by construction and provides 128-bit security.

**ChaChaPoly1305** was chosen over AES-GCM because it runs in constant time on all platforms without hardware acceleration. AES-GCM is faster with AES-NI, but Noise's sequential nonces already prevent nonce misuse, so ChaCha's performance on software-only targets is worth the tradeoff.

**BLAKE2s** was picked over SHA-256 because its 32-byte output matches X25519's key size directly, it's faster in software, and it was essentially designed for this kind of protocol. The `s` variant (as opposed to `b`) is sufficient since we never need more than 32 bytes of hash output.

No algorithm negotiation means no downgrade attacks and no implementation bugs from having multiple code paths. Both peers must agree on this ciphersuite out-of-band.

## Post-quantum modes

The `pq` feature enables two confirmed handshakes based on the [PQNoise framework](https://eprint.iacr.org/2022/539):

```
Noise_pqIKkc_MLKEM768_ChaChaPoly_BLAKE2s
Noise_hybridIKkc_25519+MLKEM768_ChaChaPoly_BLAKE2s
```

### How it works

The KEM-only suite implements optimized `pqIK`. The hybrid suite combines classical IK tokens with `pqIK`; compromise of either X25519 or ML-KEM alone does not recover the session.

```
pqIK:
  <- s_kem
  ...
  -> skem_r, ENC(e_kem_i, s_kem_i)
  <- ekem_i, ENC(skem_i), payload_r
  -> ENC(confirm, payload_i)

hybrid IK + pqIK:
  <- s_dh, s_kem
  ...
  -> skem_r, e_dh_i, es, ENC(e_kem_i, s_dh_i, s_kem_i), ss
  <- ekem_i, ENC(skem_i), e_dh_r, ee, se, payload_r
  -> ENC(confirm, payload_i)
```

The responder does not expose the claimed initiator identity, ASK, or transport keys until the third flight verifies. Message 1 cannot carry application payload, preventing the responder from consuming unauthenticated client data.

Every transmitted raw or AEAD ciphertext is mixed into the transcript, and every KEM or DH shared secret is mixed into the chaining key in pattern order.

Ephemeral ML-KEM generation, ML-KEM encapsulation, and hybrid ephemeral X25519 generation use a domain-separated KDF-SEEC profile. Each static secret stores an independent 32-byte SEEC key. Fresh 32-byte session coins are combined with that key using HMAC-BLAKE2s and HKDF expansion; static key generation continues to use the secure RNG directly. This profile hardens predictable or exposed coins while the persistent SEEC key remains secret, but does not protect against maliciously chosen or repeating entropy. Stateful or hardware-backed SEEC is the upgrade path for that threat.

### Why ML-KEM-768

ML-KEM-768 (FIPS 203) is the NIST-standardized post-quantum KEM at the 128-bit security level. Its key and ciphertext sizes are large but manageable:

| | Classical IK | KEM-only pqIK | Hybrid IK + pqIK |
|---|---:|---:|---:|
| Message 1 | 96 bytes | 3,472 bytes | 3,536 bytes |
| Message 2 | 48 bytes | 2,208 bytes | 2,240 bytes |
| Message 3 | — | 16 bytes | 16 bytes |

These sizes are already routine in practice. TLS 1.3 + ML-KEM deployments by Chrome and Cloudflare operate in the same range, and QUIC handles multi-packet Initial flights through CRYPTO frame reassembly.

### Caveats

There is no finalized Noise specification for PQ extensions, so the PQNoise paper is the best available reference. No other Noise library implements this mode, which means testing is limited to self-interop and known-answer tests with fixed randomness.

PQNoise normally transmits ephemeral public-key shares in the clear. Reishi deliberately encrypts the initiator's ephemeral ML-KEM public key together with its static keys after `skem_r` establishes an AEAD key. This hides that metadata and authenticates it earlier, but makes these custom `pqIKkc` suites wire-incompatible with a literal implementation of the paper's pattern.

Static ML-KEM keys are reused across sessions. ML-KEM is designed to support this (unlike some earlier lattice KEMs), but it is worth noting as a different model than ephemeral-only usage.

## Security considerations

**Low-order point rejection.** After every X25519 multiplication, reishi checks for the all-zeros shared secret (the identity element) in constant time using `subtle::ct_eq`. This prevents active injection of low-order public keys.

**Zeroization.** All types holding key material derive `ZeroizeOnDrop`. Intermediate HMAC/HKDF outputs use `Zeroizing<[u8; N]>` wrappers. No key material survives past `Drop`.

**HMAC construction.** Reishi uses standard RFC 2104 HMAC over BLAKE2s, not BLAKE2's built-in keyed mode. This was a deliberate choice for interoperability with `snow` and other Noise implementations.

**Classical IK replay.** A valid classical Message 1 authenticates its source but can be replayed, so responder-side authentication at that point does not establish peer freshness or liveness. Integrations should expose peer identity only after the full handshake; the Quinn integration does so.

**No panics on network input.** All code paths reachable from untrusted input return `Result::Err`. There are no `unreachable!()`, `unwrap()`, or `todo!()` calls in the handshake or transport state machines.

## Interop

The classical IK mode is tested against [snow](https://github.com/mcginty/snow), the reference Noise implementation for Rust. The PQ modes have no external implementations to test against, so they rely on self-interop, fixed SEEC vectors, tampering tests, and explicit confirmation regressions.

## Usage

```rust
use reishi_handshake::{Handshake, HandshakeAction, KeyPair};
use rand_core::OsRng;

let server_kp = KeyPair::generate(&mut OsRng);
let client_kp = KeyPair::generate(&mut OsRng);

// Client (initiator) knows server's public key
let mut client = Handshake::new_initiator(
    &client_kp,
    &server_kp.public,
    b"my-prologue",
)?;

// Server (responder)
let mut server = Handshake::new_responder(
    &server_kp,
    b"my-prologue",
)?;

// Message 1: client -> server
let mut msg1 = vec![0u8; 1024];
let len = client.write_message(b"", &mut msg1)?;
let mut payload = vec![0u8; 1024];
let plen = server.read_message(&msg1[..len], &mut payload)?;

// Message 2: server -> client
let mut msg2 = vec![0u8; 1024];
let len = server.write_message(b"", &mut msg2)?;
let plen = client.read_message(&msg2[..len], &mut payload)?;

// Both sides now have transport state
let mut client_transport = client.into_transport()?;
let mut server_transport = server.into_transport()?;
```
