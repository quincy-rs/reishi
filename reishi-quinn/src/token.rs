//! Token key implementations for QUIC stateless reset, retry, and
//! address validation tokens.
//!
//! These implement `quinn_proto::crypto::HmacKey`,
//! `quinn_proto::crypto::HandshakeTokenKey`, and
//! `quinn_proto::crypto::AeadKey`.

use quinn_proto::crypto;
use rand_core::{OsRng, RngCore};
use reishi_handshake::crypto::aead::{self, AEAD_KEY_LEN, AEAD_TAG_LEN};
use reishi_handshake::crypto::hash::{self, HASH_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// HMAC key for stateless reset token generation.
///
/// Implements `quinn_proto::crypto::HmacKey`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoiseHmacKey {
    key: [u8; HASH_LEN],
}

impl Default for NoiseHmacKey {
    fn default() -> Self {
        Self::new()
    }
}

impl NoiseHmacKey {
    /// Create a new HMAC key with random key material.
    pub fn new() -> Self {
        let mut key = [0u8; HASH_LEN];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }
}

impl crypto::HmacKey for NoiseHmacKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let sig = hash::hmac(&self.key, data);
        let copy_len = signature_out.len().min(HASH_LEN);
        signature_out[..copy_len].copy_from_slice(&sig[..copy_len]);
    }

    fn signature_len(&self) -> usize {
        HASH_LEN
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::CryptoError> {
        let expected = hash::hmac(&self.key, data);
        if subtle::ConstantTimeEq::ct_eq(&expected[..], signature).into() {
            Ok(())
        } else {
            Err(crypto::CryptoError)
        }
    }
}

/// Handshake token key for address validation token generation.
///
/// Implements `quinn_proto::crypto::HandshakeTokenKey`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoiseHandshakeTokenKey {
    key: [u8; HASH_LEN],
}

impl Default for NoiseHandshakeTokenKey {
    fn default() -> Self {
        Self::new()
    }
}

impl NoiseHandshakeTokenKey {
    /// Create a new handshake token key with random key material.
    pub fn new() -> Self {
        let mut key = [0u8; HASH_LEN];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }
}

impl crypto::HandshakeTokenKey for NoiseHandshakeTokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let derived = hash::hmac(&self.key, random_bytes);
        let mut aead_key = [0u8; AEAD_KEY_LEN];
        aead_key.copy_from_slice(&(*derived)[..AEAD_KEY_LEN]);
        Box::new(NoiseAeadKey::new(aead_key))
    }
}

/// AEAD key for token encryption.
///
/// Implements `quinn_proto::crypto::AeadKey`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoiseAeadKey {
    key: [u8; AEAD_KEY_LEN],
}

/// Length of the random salt prepended to each sealed token.
const TOKEN_SALT_LEN: usize = 16;

impl NoiseAeadKey {
    fn new(key: [u8; AEAD_KEY_LEN]) -> Self {
        Self { key }
    }

    fn derive_token_key(&self, salt: &[u8]) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
        let derived = hash::hmac(&self.key, salt);
        let mut token_key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
        token_key.copy_from_slice(&(*derived)[..AEAD_KEY_LEN]);
        token_key
    }
}

/// AEAD key for token encryption/decryption.
///
/// Used by quinn for encrypting address validation tokens.
///
/// Construction: the token stores a fresh random salt, then encrypts with
/// ChaCha20Poly1305 using an HMAC-derived per-token key and the fixed Noise
/// nonce `0`. Security: even though the nonce is fixed, the AEAD key changes
/// for every token because the salt changes, so the same key/nonce pair is
/// never reused.
impl crypto::AeadKey for NoiseAeadKey {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), crypto::CryptoError> {
        let mut salt = [0u8; TOKEN_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let token_key = self.derive_token_key(&salt);

        let plaintext_len = data.len();
        data.extend_from_slice(&[0u8; AEAD_TAG_LEN]);
        aead::encrypt_in_place(
            &token_key,
            0,
            additional_data,
            data.as_mut_slice(),
            plaintext_len,
        )
        .map_err(|_| crypto::CryptoError)?;

        let ct_len = data.len();
        data.resize(ct_len + TOKEN_SALT_LEN, 0);
        data.copy_within(0..ct_len, TOKEN_SALT_LEN);
        data[..TOKEN_SALT_LEN].copy_from_slice(&salt);
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], crypto::CryptoError> {
        if data.len() < TOKEN_SALT_LEN + AEAD_TAG_LEN {
            return Err(crypto::CryptoError);
        }

        let token_key = self.derive_token_key(&data[..TOKEN_SALT_LEN]);
        let ciphertext = &mut data[TOKEN_SALT_LEN..];
        let ciphertext_len = ciphertext.len();
        let plaintext_len =
            aead::decrypt_in_place(&token_key, 0, additional_data, ciphertext, ciphertext_len)
                .map_err(|_| crypto::CryptoError)?;
        Ok(&mut data[TOKEN_SALT_LEN..TOKEN_SALT_LEN + plaintext_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::crypto::{AeadKey, HandshakeTokenKey, HmacKey};

    #[test]
    fn hmac_sign_verify_round_trip() {
        let key = NoiseHmacKey::new();
        let data = b"test data";
        let mut sig = vec![0u8; HASH_LEN];
        key.sign(data, &mut sig);

        assert!(key.verify(data, &sig).is_ok());
    }

    #[test]
    fn hmac_verify_wrong_data_fails() {
        let key = NoiseHmacKey::new();
        let mut sig = vec![0u8; HASH_LEN];
        key.sign(b"correct", &mut sig);

        assert!(key.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn hmac_verify_wrong_sig_fails() {
        let key = NoiseHmacKey::new();
        let wrong_sig = vec![0u8; HASH_LEN];
        assert!(key.verify(b"data", &wrong_sig).is_err());
    }

    #[test]
    fn aead_seal_open_round_trip() {
        let token_key = NoiseHandshakeTokenKey::new();
        let aead = token_key.aead_from_hkdf(b"random-bytes");

        let original = b"token payload";
        let ad = b"additional data";

        let mut data = original.to_vec();
        aead.seal(&mut data, ad).unwrap();
        assert_ne!(data.as_slice(), original);

        let plaintext = aead.open(&mut data, ad).unwrap();
        assert_eq!(plaintext, original);
    }

    #[test]
    fn aead_open_wrong_ad_fails() {
        let token_key = NoiseHandshakeTokenKey::new();
        let aead = token_key.aead_from_hkdf(b"random-bytes");

        let mut data = b"payload".to_vec();
        aead.seal(&mut data, b"ad1").unwrap();

        assert!(aead.open(&mut data, b"ad2").is_err());
    }

    #[test]
    fn aead_seal_uses_salt_prefix() {
        let aead = NoiseAeadKey {
            key: [0x42u8; AEAD_KEY_LEN],
        };

        let mut data = b"payload".to_vec();
        aead.seal(&mut data, b"ad").unwrap();

        assert_eq!(data.len(), TOKEN_SALT_LEN + b"payload".len() + AEAD_TAG_LEN);

        let plaintext = aead.open(&mut data, b"ad").unwrap();
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn different_hkdf_input_gives_different_keys() {
        let token_key = NoiseHandshakeTokenKey::new();
        let aead1 = token_key.aead_from_hkdf(b"input-1");
        let aead2 = token_key.aead_from_hkdf(b"input-2");

        let mut data1 = b"payload".to_vec();
        let mut data2 = b"payload".to_vec();
        aead1.seal(&mut data1, b"").unwrap();
        aead2.seal(&mut data2, b"").unwrap();

        // Different keys should produce different ciphertexts
        assert_ne!(data1, data2);
    }
}
