# reishi-handshake

[![Crates.io](https://img.shields.io/crates/v/reishi-handshake.svg)](https://crates.io/crates/reishi-handshake)
[![Documentation](https://docs.rs/reishi-handshake/badge.svg)](https://docs.rs/reishi-handshake/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

Pure, sans-IO implementation of the [Noise Protocol](https://noiseprotocol.org/noise.html) IK handshake with optional post-quantum hybrid mode.

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

## Post-quantum hybrid mode

The `pq` feature enables a hybrid classical + post-quantum IK handshake based on the [PQNoise framework](https://eprint.iacr.org/2022/539):

```
Noise_IKpq_25519+MLKEM768_ChaChaPoly_BLAKE2s
```

### How it works

Each DH token in the standard IK pattern is augmented with a KEM operation. For every `DH(a, B)`, we also perform an ML-KEM-768 encapsulation against the corresponding KEM public key. Both shared secrets are mixed into the chaining key via `MixKey()`. Compromise of either primitive alone does not break the handshake.

The token ordering within each DH step is: `MixKey(dh_ss)`, write/read ciphertext, `MixHash(ct)`, `MixKey(kem_ss)`.

```
IKpq:
  <- s_dh, s_kem
  ...
  -> e_dh, e_kem,
     DH(e, rs) + KEM_ENCAPS(rs_kem),
     s_dh, s_kem,
     DH(s, rs) + KEM_ENCAPS(rs_kem)
  <- e_dh, e_kem,
     DH(e, ie) + KEM_ENCAPS(ie_kem),
     DH(e, is) + KEM_ENCAPS(is_kem)
```

### Why ML-KEM-768

ML-KEM-768 (FIPS 203) is the NIST-standardized post-quantum KEM at the 128-bit security level. Its key and ciphertext sizes are large but manageable:

| | Classical IK | Hybrid IK |
|---|---|---|
| Message 1 (no payload) | ~96 bytes | ~4,640 bytes |
| Message 2 (no payload) | ~48 bytes | ~3,408 bytes |

These sizes are already routine in practice. TLS 1.3 + ML-KEM deployments by Chrome and Cloudflare operate in the same range, and QUIC handles multi-packet Initial flights through CRYPTO frame reassembly.

### Caveats

There is no finalized Noise specification for PQ extensions, so the PQNoise paper is the best available reference. No other Noise library implements this mode, which means testing is limited to self-interop and known-answer tests with fixed randomness.

Static ML-KEM keys are reused across sessions. ML-KEM is designed to support this (unlike some earlier lattice KEMs), but it is worth noting as a different model than ephemeral-only usage.

## Security considerations

**Low-order point rejection.** After every X25519 multiplication, reishi checks for the all-zeros shared secret (the identity element) in constant time using `subtle::ct_eq`. This prevents active injection of low-order public keys.

**Zeroization.** All types holding key material derive `ZeroizeOnDrop`. Intermediate HMAC/HKDF outputs use `Zeroizing<[u8; N]>` wrappers. No key material survives past `Drop`.

**HMAC construction.** Reishi uses standard RFC 2104 HMAC over BLAKE2s, not BLAKE2's built-in keyed mode. This was a deliberate choice for interoperability with `snow` and other Noise implementations.

**No panics on network input.** All code paths reachable from untrusted input return `Result::Err`. There are no `unreachable!()`, `unwrap()`, or `todo!()` calls in the handshake or transport state machines.

## Interop

The classical IK mode is tested against [snow](https://github.com/mcginty/snow), the reference Noise implementation for Rust. The PQ hybrid mode has no external implementations to test against (there is no finalized Noise PQ spec yet), so it relies on self-interop and known-answer tests with fixed randomness.

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
