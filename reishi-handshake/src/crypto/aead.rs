use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use zeroize::Zeroize;

use crate::error::Error;

/// AEAD key length in bytes.
pub const AEAD_KEY_LEN: usize = 32;
/// AEAD tag length in bytes.
pub const AEAD_TAG_LEN: usize = 16;
/// AEAD nonce length in bytes.
pub const AEAD_NONCE_LEN: usize = 12;

/// Encrypt plaintext in-place, appending the 16-byte AEAD tag.
///
/// `buffer[..plaintext_len]` contains the plaintext.
/// `buffer` must have room for `plaintext_len + AEAD_TAG_LEN` bytes.
/// Returns the total ciphertext length (plaintext_len + tag).
pub fn encrypt_in_place(
    key: &[u8; AEAD_KEY_LEN],
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

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = make_nonce(nonce);

    let tag = cipher
        .encrypt_in_place_detached(&Nonce::from(nonce_bytes), ad, &mut buffer[..plaintext_len])
        .map_err(|_| Error::CryptoFailed)?;

    buffer[plaintext_len..total_len].copy_from_slice(&tag);
    Ok(total_len)
}

/// Decrypt ciphertext in-place, verifying the 16-byte AEAD tag.
///
/// `buffer[..ciphertext_len]` contains ciphertext + tag.
/// Returns the plaintext length (ciphertext_len - AEAD_TAG_LEN).
pub fn decrypt_in_place(
    key: &[u8; AEAD_KEY_LEN],
    nonce: u64,
    ad: &[u8],
    buffer: &mut [u8],
    ciphertext_len: usize,
) -> Result<usize, Error> {
    if ciphertext_len < AEAD_TAG_LEN {
        return Err(Error::BadMessage);
    }
    let plaintext_len = ciphertext_len - AEAD_TAG_LEN;

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = make_nonce(nonce);

    let (ct, tag_bytes) = buffer[..ciphertext_len].split_at_mut(plaintext_len);
    let tag = chacha20poly1305::Tag::from_slice(tag_bytes);

    cipher
        .decrypt_in_place_detached(&Nonce::from(nonce_bytes), ad, ct, tag)
        .map_err(|_| Error::CryptoFailed)?;

    Ok(plaintext_len)
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

/// Rekey function per Noise spec Section 11.3.
///
/// REKEY(k) = ENCRYPT(k, maxnonce, "", zeros)
/// where maxnonce = 2^64 - 1 and zeros = 32 zero bytes.
///
/// Returns the first 32 bytes of the output as the new key.
pub fn rekey(key: &[u8; AEAD_KEY_LEN]) -> Result<[u8; AEAD_KEY_LEN], Error> {
    let max_nonce = u64::MAX;
    let mut buffer = [0u8; AEAD_KEY_LEN + AEAD_TAG_LEN];
    encrypt_in_place(key, max_nonce, &[], &mut buffer, AEAD_KEY_LEN)?;
    let mut new_key = [0u8; AEAD_KEY_LEN];
    new_key.copy_from_slice(&buffer[..AEAD_KEY_LEN]);
    buffer.zeroize();
    Ok(new_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let plaintext = b"hello noise";
        let ad = b"associated data";

        let mut buffer = [0u8; 128];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(&key, 0, ad, &mut buffer, plaintext.len()).unwrap();
        assert_eq!(ct_len, plaintext.len() + AEAD_TAG_LEN);

        let pt_len = decrypt_in_place(&key, 0, ad, &mut buffer, ct_len).unwrap();
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&buffer[..pt_len], plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = [0x42u8; AEAD_KEY_LEN];
        let key2 = [0x43u8; AEAD_KEY_LEN];
        let plaintext = b"hello";

        let mut buffer = [0u8; 128];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(&key1, 0, &[], &mut buffer, plaintext.len()).unwrap();
        let result = decrypt_in_place(&key2, 0, &[], &mut buffer, ct_len);
        assert_eq!(result.unwrap_err(), Error::CryptoFailed);
    }

    #[test]
    fn decrypt_wrong_nonce_fails() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let plaintext = b"hello";

        let mut buffer = [0u8; 128];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(&key, 0, &[], &mut buffer, plaintext.len()).unwrap();
        let result = decrypt_in_place(&key, 1, &[], &mut buffer, ct_len);
        assert_eq!(result.unwrap_err(), Error::CryptoFailed);
    }

    #[test]
    fn encrypt_buffer_too_small() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let mut buffer = [0u8; 4]; // too small for plaintext(3) + tag(16)
        let result = encrypt_in_place(&key, 0, &[], &mut buffer, 3);
        assert_eq!(result.unwrap_err(), Error::BufferTooSmall);
    }

    #[test]
    fn decrypt_too_short() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let mut buffer = [0u8; 8]; // less than AEAD_TAG_LEN
        let result = decrypt_in_place(&key, 0, &[], &mut buffer, 8);
        assert_eq!(result.unwrap_err(), Error::BadMessage);
    }

    #[test]
    fn decrypt_wrong_ad_fails() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let plaintext = b"hello";

        let mut buffer = [0u8; 128];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let ct_len = encrypt_in_place(&key, 0, b"ad1", &mut buffer, plaintext.len()).unwrap();
        let result = decrypt_in_place(&key, 0, b"ad2", &mut buffer, ct_len);
        assert_eq!(result.unwrap_err(), Error::CryptoFailed);
    }

    #[test]
    fn encrypt_empty_plaintext() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let mut buffer = [0u8; AEAD_TAG_LEN];

        let ct_len = encrypt_in_place(&key, 0, &[], &mut buffer, 0).unwrap();
        assert_eq!(ct_len, AEAD_TAG_LEN);

        let pt_len = decrypt_in_place(&key, 0, &[], &mut buffer, ct_len).unwrap();
        assert_eq!(pt_len, 0);
    }

    #[test]
    fn rekey_produces_different_key() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let new_key = rekey(&key).unwrap();
        assert_ne!(key, new_key);
    }
}
