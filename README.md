# reishi

[![Crates.io](https://img.shields.io/crates/v/reishi-handshake.svg)](https://crates.io/crates/reishi-handshake)
[![Documentation](https://docs.rs/reishi-handshake/badge.svg)](https://docs.rs/reishi-handshake/)
[![Build status](https://github.com/quincy-rs/reishi/workflows/CI/badge.svg)](https://github.com/quincy-rs/reishi/actions?query=workflow%3ACI)
[![CodeCov](https://codecov.io/gh/quincy-rs/reishi/branch/main/graph/badge.svg)](https://codecov.io/gh/quincy-rs/reishi)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Matrix](https://img.shields.io/badge/chat-%23quincy:matrix.org-%2346BC99?logo=matrix)](https://matrix.to/#/#quincy:matrix.org)

A [Noise Protocol](https://noiseprotocol.org/noise.html) IK handshake for Rust, built for QUIC-based VPNs.

- Fixed ciphersuite: `Noise_IK_25519_ChaChaPoly_BLAKE2s` (one round trip, mutually authenticated, no negotiation)
- Optional hybrid post-quantum mode with ML-KEM-768
- Sans-IO core with a ready-made [Quinn](https://github.com/quinn-rs/quinn) crypto provider

See [DESIGN.md](./DESIGN.md) for details and the "Why?" behind these choices.

## Crates

| Crate | Description |
|-------|-------------|
| [`reishi-handshake`](./reishi-handshake) | Pure, sans-IO Noise IK handshake — takes bytes in, produces bytes out |
| [`reishi-quinn`](./reishi-quinn) | [Quinn](https://github.com/quinn-rs/quinn) crypto provider for Noise-over-QUIC |

## Usage

### Standalone handshake

```rust
use reishi_handshake::{Handshake, HandshakeAction, KeyPair};
use rand_core::OsRng;

// Generate keypairs
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

### With Quinn

```rust
use reishi_quinn::NoiseConfigBuilder;
use reishi_handshake::KeyPair;
use rand_core::OsRng;

let server_kp = KeyPair::generate(&mut OsRng);
let client_kp = KeyPair::generate(&mut OsRng);

// Server
let server_config = NoiseConfigBuilder::new(server_kp)
    .build_server_config()?;

// Client (needs the server's public key up front — that's IK)
let client_config = NoiseConfigBuilder::new(client_kp)
    .with_remote_public(server_public_key)
    .build_client_config()?;
```

## Post-quantum mode

Enable the `pq` feature for hybrid X25519 + ML-KEM-768:

```toml
[dependencies]
reishi-handshake = { version = "0.1", features = ["pq"] }
```

This gives you defense-in-depth — both primitives must be broken to compromise the handshake. Messages get bigger (~4.6 KB and ~3.4 KB), but that's in line with what Chrome and Cloudflare already ship for TLS 1.3 + ML-KEM. See the [PQ section in DESIGN.md](./DESIGN.md#post-quantum-hybrid-mode) for the full construction.

## Interop

The classical IK mode is tested against [snow](https://github.com/mcginty/snow), the reference Noise implementation for Rust. The PQ hybrid mode has no external implementations to test against (there's no finalized Noise PQ spec yet), so it relies on self-interop and known-answer tests with fixed randomness.
