# reishi

[![Crates.io](https://img.shields.io/crates/v/reishi-handshake.svg)](https://crates.io/crates/reishi-handshake)
[![Documentation](https://docs.rs/reishi-handshake/badge.svg)](https://docs.rs/reishi-handshake/)
[![Build status](https://github.com/quincy-rs/reishi/workflows/CI/badge.svg)](https://github.com/quincy-rs/reishi/actions?query=workflow%3ACI)
[![CodeCov](https://codecov.io/gh/quincy-rs/reishi/branch/main/graph/badge.svg)](https://codecov.io/gh/quincy-rs/reishi)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Matrix](https://img.shields.io/badge/chat-%23quincy:matrix.org-%2346BC99?logo=matrix)](https://matrix.to/#/#quincy:matrix.org)

A [Noise Protocol](https://noiseprotocol.org/noise.html) IK handshake for Rust, built for QUIC-based VPNs.

- Fixed classical, KEM-only, and hybrid ciphersuites with no negotiation
- Mutual authentication; confirmed PQ suites use an explicit third flight
- Sans-IO core, protocol-agnostic
- Ready-made [Quinn](https://github.com/quinn-rs/quinn) crypto provider

## Crates

| Crate | Description |
|-------|-------------|
| [`reishi-handshake`](./reishi-handshake) | Pure, sans-IO Noise IK handshake |
| [`reishi-quinn`](./reishi-quinn) | Quinn crypto provider for Noise-over-QUIC |
