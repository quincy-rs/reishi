use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroizing;

use crate::error::Error;

/// AEAD key length in bytes.
pub const AEAD_KEY_LEN: usize = 32;
/// AEAD tag length in bytes.
pub const AEAD_TAG_LEN: usize = 16;
/// AEAD nonce length in bytes.
pub const AEAD_NONCE_LEN: usize = 12;

/// ChaCha20-Poly1305 key using Noise's 64-bit counter nonce (4 zero bytes || LE u64).
///
/// Build once per key and reuse: construction allocates aws-lc's expanded key
/// context, which aws-lc wipes on drop.
pub struct AeadKey(LessSafeKey);

impl AeadKey {
    /// Import a raw 32-byte ChaCha20-Poly1305 key.
    pub fn new(key: &[u8; AEAD_KEY_LEN]) -> Self {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key)
            .expect("aws-lc accepts every 32-byte ChaCha20-Poly1305 key");
        Self(LessSafeKey::new(key))
    }

    /// Encrypt plaintext in-place, appending the 16-byte AEAD tag.
    ///
    /// `buffer[..plaintext_len]` contains the plaintext.
    /// `buffer` must have room for `plaintext_len + AEAD_TAG_LEN` bytes.
    /// Returns the total ciphertext length (plaintext_len + tag).
    pub fn encrypt_in_place(
        &self,
        nonce: u64,
        ad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, Error> {
        let total_len = plaintext_len
            .checked_add(AEAD_TAG_LEN)
            .ok_or(Error::BufferTooSmall)?;
        if buffer.len() < total_len {
            return Err(Error::BufferTooSmall);
        }

        let tag = self
            .0
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(make_nonce(nonce)),
                Aad::from(ad),
                &mut buffer[..plaintext_len],
            )
            .map_err(|_| Error::CryptoFailed)?;

        buffer[plaintext_len..total_len].copy_from_slice(tag.as_ref());
        Ok(total_len)
    }

    /// Decrypt ciphertext in-place, verifying the 16-byte AEAD tag.
    ///
    /// `buffer[..ciphertext_len]` contains ciphertext + tag.
    /// Returns the plaintext length (ciphertext_len - AEAD_TAG_LEN).
    pub fn decrypt_in_place(
        &self,
        nonce: u64,
        ad: &[u8],
        buffer: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, Error> {
        if ciphertext_len < AEAD_TAG_LEN {
            return Err(Error::BadMessage);
        }
        let plaintext_len = ciphertext_len - AEAD_TAG_LEN;

        let (ciphertext, tag) = buffer[..ciphertext_len].split_at_mut(plaintext_len);
        self.0
            .open_in_place_separate_tag(
                Nonce::assume_unique_for_key(make_nonce(nonce)),
                Aad::from(ad),
                tag,
                ciphertext,
            )
            .map_err(|_| Error::CryptoFailed)?;

        Ok(plaintext_len)
    }

    /// Rekey per Noise spec Section 11.3.
    ///
    /// REKEY(k) = first 32 bytes of ENCRYPT(k, 2^64-1, "", zeros).
    pub fn rekey(&self) -> Result<Self, Error> {
        let mut buffer = Zeroizing::new([0u8; AEAD_KEY_LEN + AEAD_TAG_LEN]);
        self.encrypt_in_place(u64::MAX, &[], &mut buffer[..], AEAD_KEY_LEN)?;
        Ok(Self::new(
            buffer[..AEAD_KEY_LEN]
                .try_into()
                .expect("slice is AEAD_KEY_LEN bytes"),
        ))
    }
}

/// Build the 12-byte nonce from a u64 counter.
///
/// 4 bytes of zeros followed by the 64-bit little-endian counter,
/// per Noise spec Section 5.1 for ChaChaPoly (12-byte nonce total).
fn make_nonce(n: u64) -> [u8; AEAD_NONCE_LEN] {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = AeadKey::new(&[0x42u8; AEAD_KEY_LEN]);
        let plaintext = b"hello noise";
        let ad = b"associated data";

        let mut buffer = [0u8; 128];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = key
            .encrypt_in_place(0, ad, &mut buffer, plaintext.len())
            .unwrap();
        assert_eq!(ct_len, plaintext.len() + AEAD_TAG_LEN);

        let pt_len = key.decrypt_in_place(0, ad, &mut buffer, ct_len).unwrap();
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&buffer[..pt_len], plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = AeadKey::new(&[0x42u8; AEAD_KEY_LEN]);
        let key2 = AeadKey::new(&[0x43u8; AEAD_KEY_LEN]);
        let plaintext = b"hello";

        let mut buffer = [0u8; 128];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = key1
            .encrypt_in_place(0, &[], &mut buffer, plaintext.len())
            .unwrap();
        let result = key2.decrypt_in_place(0, &[], &mut buffer, ct_len);
        assert_eq!(result.unwrap_err(), Error::CryptoFailed);
    }

    #[test]
    fn decrypt_wrong_nonce_fails() {
        let key = AeadKey::new(&[0x42u8; AEAD_KEY_LEN]);
        let plaintext = b"hello";

        let mut buffer = [0u8; 128];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = key
            .encrypt_in_place(0, &[], &mut buffer, plaintext.len())
            .unwrap();
        let result = key.decrypt_in_place(1, &[], &mut buffer, ct_len);
        assert_eq!(result.unwrap_err(), Error::CryptoFailed);
    }

    #[test]
    fn encrypt_buffer_too_small() {
        let key = AeadKey::new(&[0x42u8; AEAD_KEY_LEN]);
        let mut buffer = [0u8; 4]; // too small for plaintext(3) + tag(16)
        let result = key.encrypt_in_place(0, &[], &mut buffer, 3);
        assert_eq!(result.unwrap_err(), Error::BufferTooSmall);
    }

    #[test]
    fn decrypt_too_short() {
        let key = AeadKey::new(&[0x42u8; AEAD_KEY_LEN]);
        let mut buffer = [0u8; 8]; // less than AEAD_TAG_LEN
        let result = key.decrypt_in_place(0, &[], &mut buffer, 8);
        assert_eq!(result.unwrap_err(), Error::BadMessage);
    }

    #[test]
    fn decrypt_wrong_ad_fails() {
        let key = AeadKey::new(&[0x42u8; AEAD_KEY_LEN]);
        let plaintext = b"hello";

        let mut buffer = [0u8; 128];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = key
            .encrypt_in_place(0, b"ad1", &mut buffer, plaintext.len())
            .unwrap();
        let result = key.decrypt_in_place(0, b"ad2", &mut buffer, ct_len);
        assert_eq!(result.unwrap_err(), Error::CryptoFailed);
    }

    #[test]
    fn encrypt_empty_plaintext() {
        let key = AeadKey::new(&[0x42u8; AEAD_KEY_LEN]);
        let mut buffer = [0u8; AEAD_TAG_LEN];

        let ct_len = key.encrypt_in_place(0, &[], &mut buffer, 0).unwrap();
        assert_eq!(ct_len, AEAD_TAG_LEN);

        let pt_len = key.decrypt_in_place(0, &[], &mut buffer, ct_len).unwrap();
        assert_eq!(pt_len, 0);
    }

    #[test]
    fn rekey_matches_noise_definition() {
        let key = AeadKey::new(&[0x42u8; AEAD_KEY_LEN]);

        let mut rekey_block = [0u8; AEAD_KEY_LEN + AEAD_TAG_LEN];
        key.encrypt_in_place(u64::MAX, &[], &mut rekey_block, AEAD_KEY_LEN)
            .unwrap();
        let expected: [u8; AEAD_KEY_LEN] = rekey_block[..AEAD_KEY_LEN].try_into().unwrap();

        let encrypt_with = |key: &AeadKey| {
            let mut buffer = [0u8; 5 + AEAD_TAG_LEN];
            buffer[..5].copy_from_slice(b"hello");
            key.encrypt_in_place(0, &[], &mut buffer, 5).unwrap();
            buffer
        };

        let rekeyed = encrypt_with(&key.rekey().unwrap());
        assert_eq!(rekeyed, encrypt_with(&AeadKey::new(&expected)));
        assert_ne!(rekeyed, encrypt_with(&key));
    }
}
