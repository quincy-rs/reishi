//! QUIC packet and header protection key implementations.
//!
//! Provides `NoisePacketKey` and `NoiseHeaderKey` which implement the
//! `quinn_proto::crypto::PacketKey` and `quinn_proto::crypto::HeaderKey`
//! traits respectively, using ChaChaPoly1305 and SHA-512.

use aws_lc_rs::aead::quic::{CHACHA20, HeaderProtectionKey};
use quinn_proto::crypto;
use reishi_handshake::crypto::aead::{AEAD_KEY_LEN, AEAD_TAG_LEN, AeadKey};
use reishi_handshake::crypto::hash::HASH_LEN;

use crate::initial::derive_key_pair;

/// Header protection sample size.
///
/// ChaChaPoly uses a 16-byte sample for header protection (same as AES-based
/// QUIC header protection).
pub const HEADER_SAMPLE_LEN: usize = 16;

/// AEAD packet key implementing `quinn_proto::crypto::PacketKey`.
pub struct NoisePacketKey {
    key: AeadKey,
}

impl NoisePacketKey {
    /// Create a new packet key from raw key material.
    pub fn new(key: &[u8; AEAD_KEY_LEN]) -> Self {
        Self {
            key: AeadKey::new(key),
        }
    }

    /// Wrap in a Box for use in `crypto::KeyPair`.
    pub fn boxed(key: &[u8; AEAD_KEY_LEN]) -> Box<dyn crypto::PacketKey> {
        Box::new(Self::new(key))
    }
}

impl crypto::PacketKey for NoisePacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload) = buf.split_at_mut(header_len);
        let plaintext_len = payload
            .len()
            .checked_sub(AEAD_TAG_LEN)
            .expect("payload too short for AEAD tag");
        self.key
            .encrypt_in_place(packet, header, payload, plaintext_len)
            .expect("packet encryption should not fail");
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut bytes::BytesMut,
    ) -> Result<(), crypto::CryptoError> {
        let buffer = payload.as_mut();
        let ciphertext_len = buffer.len();
        let plaintext_len = self
            .key
            .decrypt_in_place(packet, header, buffer, ciphertext_len)
            .map_err(|_| crypto::CryptoError)?;
        payload.truncate(plaintext_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        // Conservative bound matching the QUIC TLS specification for
        // ChaChaPoly: 2^25 packets (RFC 9001 Section 6.6).
        1 << 25
    }

    fn integrity_limit(&self) -> u64 {
        // ChaCha20-Poly1305 integrity limit per QUIC spec: 2^36.
        1 << 36
    }
}

/// Header protection key implementing `quinn_proto::crypto::HeaderKey`.
///
/// Uses ChaCha20 to derive a 5-byte mask from a 16-byte sample, matching
/// the QUIC header protection scheme for ChaCha20-based ciphersuites
/// (RFC 9001 Section 5.4.4).
pub struct NoiseHeaderKey {
    key: HeaderProtectionKey,
}

impl NoiseHeaderKey {
    /// Create a new header protection key from raw key material.
    pub fn new(key: &[u8; AEAD_KEY_LEN]) -> Self {
        Self {
            key: HeaderProtectionKey::new(&CHACHA20, key)
                .expect("aws-lc accepts every 32-byte ChaCha20 header-protection key"),
        }
    }

    /// Wrap in a Box for use in `crypto::KeyPair`.
    pub fn boxed(key: &[u8; AEAD_KEY_LEN]) -> Box<dyn crypto::HeaderKey> {
        Box::new(Self::new(key))
    }

    /// Compute the 5-byte header protection mask from a 16-byte sample
    /// (RFC 9001 Section 5.4.4).
    fn header_protection_mask(&self, sample: &[u8]) -> [u8; 5] {
        self.key
            .new_mask(sample)
            .expect("header protection sample is HEADER_SAMPLE_LEN bytes")
    }

    /// Apply header protection (encryption or decryption).
    fn apply(&self, encrypt: bool, pn_offset: usize, packet: &mut [u8]) {
        let sample_start = pn_offset + 4;
        if sample_start + HEADER_SAMPLE_LEN > packet.len() {
            return;
        }

        let sample: [u8; HEADER_SAMPLE_LEN] = packet
            [sample_start..sample_start + HEADER_SAMPLE_LEN]
            .try_into()
            .unwrap();

        let mask = self.header_protection_mask(&sample);

        let header_0_orig = packet[0];
        if packet[0] & 0x80 == 0x80 {
            // Long header: mask low 4 bits
            packet[0] ^= mask[0] & 0x0f;
        } else {
            // Short header: mask low 5 bits
            packet[0] ^= mask[0] & 0x1f;
        }

        // When encrypting, use original first byte; when decrypting, use unprotected
        let pn_len = if encrypt {
            (header_0_orig & 0x03) as usize + 1
        } else {
            (packet[0] & 0x03) as usize + 1
        };

        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    }
}

impl crypto::HeaderKey for NoiseHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(false, pn_offset, packet);
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(true, pn_offset, packet);
    }

    fn sample_size(&self) -> usize {
        HEADER_SAMPLE_LEN
    }
}

/// Build a full `crypto::Keys` from a level secret and the local side.
pub fn keys_from_level_secret(
    local_is_initiator: bool,
    level_secret: &[u8; HASH_LEN],
) -> crypto::Keys {
    let (init_keys, resp_keys) = derive_key_pair(level_secret);

    let (local_keys, remote_keys) = if local_is_initiator {
        (init_keys, resp_keys)
    } else {
        (resp_keys, init_keys)
    };

    crypto::Keys {
        header: crypto::KeyPair {
            local: NoiseHeaderKey::boxed(&local_keys.header_key),
            remote: NoiseHeaderKey::boxed(&remote_keys.header_key),
        },
        packet: crypto::KeyPair {
            local: NoisePacketKey::boxed(&local_keys.packet_key),
            remote: NoisePacketKey::boxed(&remote_keys.packet_key),
        },
    }
}

/// Build only packet keys from a level secret (for key updates).
pub fn packet_keys_from_level_secret(
    local_is_initiator: bool,
    level_secret: &[u8; HASH_LEN],
) -> crypto::KeyPair<Box<dyn crypto::PacketKey>> {
    let (init_keys, resp_keys) = derive_key_pair(level_secret);

    let (local_keys, remote_keys) = if local_is_initiator {
        (init_keys, resp_keys)
    } else {
        (resp_keys, init_keys)
    };

    crypto::KeyPair {
        local: NoisePacketKey::boxed(&local_keys.packet_key),
        remote: NoisePacketKey::boxed(&remote_keys.packet_key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::crypto::HeaderKey;

    #[test]
    fn chacha20_header_protection_matches_rfc9001_a5() {
        let key = NoiseHeaderKey::new(&[
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc,
            0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b,
            0x0a, 0xb7, 0xa7, 0xa4,
        ]);
        let mut packet = [
            0x42, 0x00, 0xbf, 0xf4, 0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57,
            0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb,
        ];

        // Short header with an empty DCID: the packet number starts at byte 1.
        key.encrypt(1, &mut packet);
        assert_eq!(packet[..4], [0x4c, 0xfe, 0x41, 0x89]);

        key.decrypt(1, &mut packet);
        assert_eq!(packet[..4], [0x42, 0x00, 0xbf, 0xf4]);
    }
}
