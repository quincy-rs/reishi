# Design

Reishi is a clean-room Noise IK handshake implementation, inspired by [hyphae-handshake](https://github.com/WillBuik/hyphae-handshake). This document explains the protocol choices and their rationale.

## The IK Pattern

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

## Post-Quantum Hybrid Mode

The `pq` feature enables a hybrid classical + post-quantum IK handshake based on the [PQNoise framework](https://eprint.iacr.org/2022/539):

```
Noise_IKpq_25519+MLKEM768_ChaChaPoly_BLAKE2s
```

### How It Works

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

These sizes are already routine in practice -- TLS 1.3 + ML-KEM deployments by Chrome and Cloudflare operate in the same range, and QUIC handles multi-packet Initial flights through CRYPTO frame reassembly.

### Caveats

There is no finalized Noise specification for PQ extensions, so the PQNoise paper is the best available reference. No other Noise library implements this mode, which means testing is limited to self-interop and known-answer tests with fixed randomness.

Static ML-KEM keys are reused across sessions. ML-KEM is designed to support this (unlike some earlier lattice KEMs), but it is worth noting as a different model than ephemeral-only usage.

## QUIC Integration

### Version Negotiation

Reishi connections use custom QUIC version numbers to distinguish themselves from TLS 1.3:

```
REISHI_V1_QUIC_V1:    0x52510101  // "RQ\x01\x01"
REISHI_PQ_V1_QUIC_V1: 0x52510201  // "RQ\x02\x01" (pq feature)
```

### Key Derivation

QUIC needs multiple key levels (initial, handshake, 1-RTT), each with separate header protection and packet protection keys for both directions. Reishi derives these using the Noise ASK (Additional Symmetric Keys) mechanism, which extracts extra keys from the chaining key via HKDF with domain-separated labels:

1. **Initial keys** -- derived from the client's Destination Connection ID with label `"reishi initial"`
2. **Handshake keys** -- derived from the Noise chaining key after Message 1, with label `"reishi key"`
3. **1-RTT keys** -- derived from the next chaining key after Message 2
4. **Rekeying** -- uses Noise's built-in `rekey()` for key updates

Each level produces four subkeys: `"init hp"`, `"resp hp"`, `"init data"`, `"resp data"`.

### Transport Parameters

Both sides exchange QUIC transport parameters inside Noise handshake payloads -- the initiator in Message 1, the responder in Message 2. Since IK is a two-message pattern and both messages carry encrypted payloads, no deferral is needed.

### Framing

Handshake messages are prefixed with a QUIC VarInt length for transmission over CRYPTO frames:

```
[VarInt length][message bytes]
```

## Security Considerations

**Low-order point rejection.** After every X25519 multiplication, reishi checks for the all-zeros shared secret (the identity element) in constant time using `subtle::ct_eq`. This prevents active injection of low-order public keys.

**Zeroization.** All types holding key material derive `ZeroizeOnDrop`. Intermediate HMAC/HKDF outputs use `Zeroizing<[u8; N]>` wrappers. No key material survives past `Drop`.

**HMAC construction.** Reishi uses standard RFC 2104 HMAC over BLAKE2s, not BLAKE2's built-in keyed mode. This was a deliberate choice for interoperability with `snow` and other Noise implementations.

**No panics on network input.** All code paths reachable from untrusted input return `Result::Err`. There are no `unreachable!()`, `unwrap()`, or `todo!()` calls in the handshake or transport state machines.
