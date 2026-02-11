# reishi-quinn

[![Crates.io](https://img.shields.io/crates/v/reishi-quinn.svg)](https://crates.io/crates/reishi-quinn)
[![Documentation](https://docs.rs/reishi-quinn/badge.svg)](https://docs.rs/reishi-quinn/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

[Quinn](https://github.com/quinn-rs/quinn) crypto provider that replaces TLS 1.3 with Noise IK from [`reishi-handshake`](https://crates.io/crates/reishi-handshake).

## QUIC integration

### Version negotiation

Reishi connections use custom QUIC version numbers to distinguish themselves from TLS 1.3:

```
REISHI_V1_QUIC_V1:    0x52510101  // "RQ\x01\x01"
REISHI_PQ_V1_QUIC_V1: 0x52510201  // "RQ\x02\x01" (pq feature)
```

### Key derivation

QUIC needs multiple key levels (initial, handshake, 1-RTT), each with separate header protection and packet protection keys for both directions. Reishi derives these using the Noise ASK (Additional Symmetric Keys) mechanism, which extracts extra keys from the chaining key via HKDF with domain-separated labels:

1. **Initial keys**: derived from the client's Destination Connection ID with label `"reishi initial"`
2. **Handshake keys**: derived from the Noise chaining key after Message 1, with label `"reishi key"`
3. **1-RTT keys**: derived from the next chaining key after Message 2
4. **Rekeying**: uses Noise's built-in `rekey()` for key updates

Each level produces four subkeys: `"init hp"`, `"resp hp"`, `"init data"`, `"resp data"`.

### Transport parameters

Both sides exchange QUIC transport parameters inside Noise handshake payloads: the initiator in Message 1, the responder in Message 2. Since IK is a two-message pattern and both messages carry encrypted payloads, no deferral is needed.

### Framing

Handshake messages are prefixed with a QUIC VarInt length for transmission over CRYPTO frames:

```
[VarInt length][message bytes]
```

## Usage

```rust
use reishi_quinn::NoiseConfigBuilder;
use reishi_handshake::KeyPair;
use rand_core::OsRng;

let server_kp = KeyPair::generate(&mut OsRng);
let client_kp = KeyPair::generate(&mut OsRng);

// Or load from existing secret key material
// let server_kp = KeyPair::from_secret_bytes(secret_bytes);
// let client_kp = KeyPair::from_secret_bytes(secret_bytes);

// Server
let server_config = NoiseConfigBuilder::new(server_kp)
    .build_server_config()?;

// Client (needs the server's public key up front, that's IK)
let client_config = NoiseConfigBuilder::new(client_kp)
    .with_remote_public(server_public_key)
    .build_client_config()?;
```
