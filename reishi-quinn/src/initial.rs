//! Initial key derivation from QUIC connection IDs.
//!
//! Derives the initial encryption keys that protect the Initial packet
//! space before the Noise handshake produces keying material.

use rand_core::RngCore;
use reishi_handshake::crypto::aead::AEAD_KEY_LEN;
use reishi_handshake::crypto::hash::{HASH_LEN, hkdf2};
use zeroize::Zeroize;

use crate::{INIT_DATA_LABEL, INIT_HP_LABEL, INITIAL_LABEL, RESP_DATA_LABEL, RESP_HP_LABEL};

/// Derive the initial level secret from the QUIC version and client's
/// destination CID.
///
/// Analogous to TLS 1.3's `initial_secret` derivation, but uses
/// HKDF-BLAKE2s with the label `"reishi initial"`. The version is
/// mixed into the IKM to provide domain separation between standard
/// and PQ modes.
pub fn initial_level_secret(version: u32, client_dcid: &[u8]) -> [u8; HASH_LEN] {
    let salt = reishi_handshake::crypto::hash::hash(INITIAL_LABEL);
    let mut ikm = Vec::with_capacity(4 + client_dcid.len());
    ikm.extend_from_slice(&version.to_be_bytes());
    ikm.extend_from_slice(client_dcid);
    let (secret, _) = hkdf2(&salt, &ikm);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&*secret);
    out
}

/// Derive a subkey from a level secret using HKDF with the given label.
pub fn derive_subkey(level_secret: &[u8; HASH_LEN], label: &[u8]) -> [u8; AEAD_KEY_LEN] {
    let (derived, _) = hkdf2(level_secret, label);
    let mut key = [0u8; AEAD_KEY_LEN];
    key.copy_from_slice(&(*derived)[..AEAD_KEY_LEN]);
    key
}

/// Key material for one side (initiator or responder) at a given level.
pub struct DirectionalKeys {
    pub packet_key: [u8; AEAD_KEY_LEN],
    pub header_key: [u8; AEAD_KEY_LEN],
}

impl Drop for DirectionalKeys {
    fn drop(&mut self) {
        self.packet_key.zeroize();
        self.header_key.zeroize();
    }
}

/// Derive initiator and responder keys from a level secret.
pub fn derive_key_pair(level_secret: &[u8; HASH_LEN]) -> (DirectionalKeys, DirectionalKeys) {
    let init_keys = DirectionalKeys {
        packet_key: derive_subkey(level_secret, INIT_DATA_LABEL),
        header_key: derive_subkey(level_secret, INIT_HP_LABEL),
    };
    let resp_keys = DirectionalKeys {
        packet_key: derive_subkey(level_secret, RESP_DATA_LABEL),
        header_key: derive_subkey(level_secret, RESP_HP_LABEL),
    };
    (init_keys, resp_keys)
}

/// Derive the retry tag key from the original destination connection ID.
pub fn retry_tag_key(orig_dst_cid: &[u8]) -> [u8; AEAD_KEY_LEN] {
    let salt = reishi_handshake::crypto::hash::hash(crate::RETRY_LABEL);
    let (key_material, _) = hkdf2(&salt, orig_dst_cid);
    let mut key = [0u8; AEAD_KEY_LEN];
    key.copy_from_slice(&(*key_material)[..AEAD_KEY_LEN]);
    key
}

/// Compute a retry tag for the given packet using AEAD encryption.
///
/// Returns the 16-byte authentication tag over `packet` using a key
/// derived from `orig_dst_cid`.
pub fn compute_retry_tag(
    orig_dst_cid: &quinn_proto::ConnectionId,
    packet: &[u8],
) -> [u8; reishi_handshake::crypto::aead::AEAD_TAG_LEN] {
    let key = retry_tag_key(orig_dst_cid);

    let plaintext_len = packet.len();
    let mut buf = Vec::with_capacity(plaintext_len + reishi_handshake::crypto::aead::AEAD_TAG_LEN);
    buf.extend_from_slice(packet);
    buf.extend_from_slice(&[0u8; reishi_handshake::crypto::aead::AEAD_TAG_LEN]);

    // Buffer is always correctly sized: plaintext_len + AEAD_TAG_LEN.
    // If encryption somehow fails, return a random-looking tag rather than panicking.
    if reishi_handshake::crypto::aead::encrypt_in_place(&key, 0, b"", &mut buf, plaintext_len)
        .is_err()
    {
        let mut tag = [0u8; reishi_handshake::crypto::aead::AEAD_TAG_LEN];
        rand_core::OsRng.fill_bytes(&mut tag);
        return tag;
    }

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&buf[plaintext_len..]);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_secret_deterministic() {
        let s1 = initial_level_secret(0x52510101, b"dcid-1234");
        let s2 = initial_level_secret(0x52510101, b"dcid-1234");
        assert_eq!(s1, s2);
    }

    #[test]
    fn initial_secret_different_dcids() {
        let s1 = initial_level_secret(0x52510101, b"dcid-1");
        let s2 = initial_level_secret(0x52510101, b"dcid-2");
        assert_ne!(s1, s2);
    }

    #[test]
    fn initial_secret_different_versions() {
        let s1 = initial_level_secret(0x52510101, b"dcid-1");
        let s2 = initial_level_secret(0x52510201, b"dcid-1");
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_subkey_deterministic() {
        let secret = [0x42u8; HASH_LEN];
        let k1 = derive_subkey(&secret, b"label");
        let k2 = derive_subkey(&secret, b"label");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_subkey_different_labels() {
        let secret = [0x42u8; HASH_LEN];
        let k1 = derive_subkey(&secret, b"label1");
        let k2 = derive_subkey(&secret, b"label2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_key_pair_produces_different_keys() {
        let secret = [0x42u8; HASH_LEN];
        let (init, resp) = derive_key_pair(&secret);
        assert_ne!(init.packet_key, resp.packet_key);
        assert_ne!(init.header_key, resp.header_key);
        assert_ne!(init.packet_key, init.header_key);
    }

    #[test]
    fn retry_tag_key_deterministic() {
        let k1 = retry_tag_key(b"orig-dcid");
        let k2 = retry_tag_key(b"orig-dcid");
        assert_eq!(k1, k2);
    }

    #[test]
    fn retry_tag_key_different_cids() {
        let k1 = retry_tag_key(b"cid-1");
        let k2 = retry_tag_key(b"cid-2");
        assert_ne!(k1, k2);
    }
}
