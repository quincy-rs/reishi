//! QUIC packet and header protection key implementations.
//!
//! Provides `NoisePacketKey` and `NoiseHeaderKey` which implement the
//! `quinn_proto::crypto::PacketKey` and `quinn_proto::crypto::HeaderKey`
//! traits respectively, using ChaChaPoly1305 and BLAKE2s.

use quinn_proto::crypto;
use reishi_handshake::crypto::aead::{self, AEAD_KEY_LEN, AEAD_TAG_LEN};
use reishi_handshake::crypto::hash::HASH_LEN;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::initial::derive_key_pair;

/// Header protection sample size.
///
/// ChaChaPoly uses a 16-byte sample for header protection (same as AES-based
/// QUIC header protection).
pub const HEADER_SAMPLE_LEN: usize = 16;

/// AEAD packet key implementing `quinn_proto::crypto::PacketKey`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoisePacketKey {
    key: [u8; AEAD_KEY_LEN],
}

impl NoisePacketKey {
    /// Create a new packet key from raw key material.
    pub fn new(key: [u8; AEAD_KEY_LEN]) -> Self {
        Self { key }
    }

    /// Wrap in a Box for use in `crypto::KeyPair`.
    pub fn boxed(key: [u8; AEAD_KEY_LEN]) -> Box<dyn crypto::PacketKey> {
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
        aead::encrypt_in_place(&self.key, packet, header, payload, plaintext_len)
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
        let plaintext_len =
            aead::decrypt_in_place(&self.key, packet, header, buffer, ciphertext_len)
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
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoiseHeaderKey {
    key: [u8; AEAD_KEY_LEN],
}

impl NoiseHeaderKey {
    /// Create a new header protection key from raw key material.
    pub fn new(key: [u8; AEAD_KEY_LEN]) -> Self {
        Self { key }
    }

    /// Wrap in a Box for use in `crypto::KeyPair`.
    pub fn boxed(key: [u8; AEAD_KEY_LEN]) -> Box<dyn crypto::HeaderKey> {
        Box::new(Self::new(key))
    }

    /// Compute the 5-byte header protection mask from a 16-byte sample.
    ///
    /// For ChaCha20-based protection, the sample is used as a nonce+counter
    /// input to ChaCha20 to generate the mask.
    fn header_protection_mask(&self, sample: &[u8]) -> [u8; 5] {
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        // RFC 9001 Section 5.4.4: ChaCha20 header protection
        // counter = sample[0..4] as little-endian u32
        // nonce = sample[4..16]
        // mask = ChaCha20(key, counter, nonce, 5 zero bytes)
        let counter = u32::from_le_bytes(sample[0..4].try_into().unwrap());
        let nonce: [u8; 12] = sample[4..16].try_into().unwrap();

        let mut mask = [0u8; 5];
        let mut cipher =
            chacha20::ChaCha20::new_from_slices(&self.key, &nonce).expect("valid key/nonce");
        // seek() takes a byte offset; each ChaCha20 block is 64 bytes,
        // so multiply the block counter by 64 to get the byte position.
        use chacha20::cipher::StreamCipherSeek;
        cipher.seek(counter as u64 * 64);
        cipher.apply_keystream(&mut mask);
        mask
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
            local: NoiseHeaderKey::boxed(local_keys.header_key),
            remote: NoiseHeaderKey::boxed(remote_keys.header_key),
        },
        packet: crypto::KeyPair {
            local: NoisePacketKey::boxed(local_keys.packet_key),
            remote: NoisePacketKey::boxed(remote_keys.packet_key),
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
        local: NoisePacketKey::boxed(local_keys.packet_key),
        remote: NoisePacketKey::boxed(remote_keys.packet_key),
    }
}
