//! ML-KEM-768 through aws-lc-rs.
//!
//! Randomness for key generation and encapsulation comes from aws-lc's CSPRNG.
//! Static keys persist as the FIPS 203 expanded decapsulation key because
//! aws-lc-rs cannot import 64-byte seeds.

use aws_lc_rs::digest;
use aws_lc_rs::kem::{self, AlgorithmId, Ciphertext, ML_KEM_768};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;

/// Serialized length of an ML-KEM-768 encapsulation key.
pub const KEM_EK_LEN: usize = 1184;

/// Serialized length of an ML-KEM-768 expanded decapsulation key (FIPS 203).
pub const KEM_DK_LEN: usize = 2400;

/// Serialized length of an ML-KEM-768 ciphertext.
pub const KEM_CT_LEN: usize = 1088;

/// Length of an ML-KEM-768 shared secret.
pub const KEM_SS_LEN: usize = 32;

/// Offset of `ek` inside the FIPS 203 dk layout `dk_PKE(1152) || ek(1184) || H(ek)(32) || z(32)`.
const KEM_DK_EK_OFFSET: usize = 1152;

/// Offset of the stored `H(ek)` inside the expanded decapsulation key.
const KEM_DK_HASH_OFFSET: usize = KEM_DK_EK_OFFSET + KEM_EK_LEN;

/// Length of the stored `H(ek)` (SHA3-256).
const KEM_DK_HASH_LEN: usize = 32;

/// Zeroizing shared secret returned by ML-KEM encapsulation or decapsulation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemSharedSecret([u8; KEM_SS_LEN]);

impl KemSharedSecret {
    /// Borrow the shared secret for immediate transcript-key mixing.
    pub fn as_bytes(&self) -> &[u8; KEM_SS_LEN] {
        &self.0
    }

    /// Copy an aws-lc shared secret into zeroizing storage.
    fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut shared_secret = [0u8; KEM_SS_LEN];
        if bytes.len() != KEM_SS_LEN {
            return Err(Error::CryptoFailed);
        }
        shared_secret.copy_from_slice(bytes);
        Ok(Self(shared_secret))
    }
}

/// Generate a static ML-KEM-768 keypair as `(expanded_dk, ek)`.
pub fn kem_generate() -> (Zeroizing<[u8; KEM_DK_LEN]>, [u8; KEM_EK_LEN]) {
    let key = kem::DecapsulationKey::generate(&ML_KEM_768).expect("aws-lc ML-KEM keygen failed");
    let key_bytes = key
        .key_bytes()
        .expect("aws-lc exports every generated ML-KEM key");

    let mut dk = Zeroizing::new([0u8; KEM_DK_LEN]);
    dk.copy_from_slice(key_bytes.as_ref());
    let ek = kem_ek_from_dk(&dk);

    (dk, ek)
}

/// Extract the encapsulation key embedded in an expanded decapsulation key.
pub fn kem_ek_from_dk(dk: &[u8; KEM_DK_LEN]) -> [u8; KEM_EK_LEN] {
    let mut ek = [0u8; KEM_EK_LEN];
    ek.copy_from_slice(&dk[KEM_DK_EK_OFFSET..KEM_DK_HASH_OFFSET]);
    ek
}

/// Import an expanded decapsulation key into aws-lc.
///
/// Only checks the length; use [`kem_validate_dk`] for untrusted input.
pub(crate) fn kem_decapsulation_key(
    dk: &[u8; KEM_DK_LEN],
) -> Result<kem::DecapsulationKey<AlgorithmId>, Error> {
    kem::DecapsulationKey::new(&ML_KEM_768, &dk[..]).map_err(|_| Error::BadKey)
}

/// Reject an imported expanded ML-KEM-768 key that is internally inconsistent.
///
/// Runs the FIPS 203 §7.3 hash check (stored H(ek) == SHA3-256(ek)) and one pairwise
/// consistency test: encapsulate to the embedded ek, decapsulate with the key, and compare.
/// This catches corrupted, truncated-and-padded or mixed-up key files at load time.
pub(crate) fn kem_validate_dk(dk: &[u8; KEM_DK_LEN]) -> Result<(), Error> {
    let ek_hash = digest::digest(&digest::SHA3_256, &dk[KEM_DK_EK_OFFSET..KEM_DK_HASH_OFFSET]);
    if ek_hash.as_ref() != &dk[KEM_DK_HASH_OFFSET..KEM_DK_HASH_OFFSET + KEM_DK_HASH_LEN] {
        return Err(Error::BadKey);
    }

    let ek = kem_ek_from_dk(dk);
    let key = kem_decapsulation_key(dk)?;
    let (ciphertext, sent) = kem_encapsulate(&ek).map_err(|_| Error::BadKey)?;
    let received = kem_decapsulate(&key, &ciphertext).map_err(|_| Error::BadKey)?;
    if !bool::from(sent.as_bytes().ct_eq(received.as_bytes())) {
        return Err(Error::BadKey);
    }

    Ok(())
}

/// Generate an ephemeral ML-KEM keypair, returning the aws-lc key and its ek bytes.
pub(crate) fn kem_generate_ephemeral()
-> Result<(kem::DecapsulationKey<AlgorithmId>, [u8; KEM_EK_LEN]), Error> {
    let key = kem::DecapsulationKey::generate(&ML_KEM_768).map_err(|_| Error::CryptoFailed)?;
    let ek_bytes = key
        .encapsulation_key()
        .and_then(|ek| ek.key_bytes())
        .map_err(|_| Error::CryptoFailed)?;
    let ek = ek_bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::CryptoFailed)?;

    Ok((key, ek))
}

/// Encapsulate to a remote ML-KEM-768 encapsulation key.
///
/// Returns `Error::BadKey` for malformed keys; aws-lc runs the FIPS 203 §7.2
/// modulus check during encapsulation.
pub(crate) fn kem_encapsulate(
    remote: &[u8; KEM_EK_LEN],
) -> Result<([u8; KEM_CT_LEN], KemSharedSecret), Error> {
    let key = kem::EncapsulationKey::new(&ML_KEM_768, remote).map_err(|_| Error::BadKey)?;
    let (ciphertext, shared_secret) = key.encapsulate().map_err(|_| Error::BadKey)?;

    let ciphertext = ciphertext
        .as_ref()
        .try_into()
        .map_err(|_| Error::CryptoFailed)?;

    Ok((
        ciphertext,
        KemSharedSecret::from_slice(shared_secret.as_ref())?,
    ))
}

/// Recover an ML-KEM shared secret from a ciphertext and static or ephemeral key.
pub(crate) fn kem_decapsulate(
    dk: &kem::DecapsulationKey<AlgorithmId>,
    ciphertext: &[u8; KEM_CT_LEN],
) -> Result<KemSharedSecret, Error> {
    let shared_secret = dk
        .decapsulate(Ciphertext::from(&ciphertext[..]))
        .map_err(|_| Error::CryptoFailed)?;

    KemSharedSecret::from_slice(shared_secret.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restored_expanded_key_round_trips() {
        let key = kem::DecapsulationKey::generate(&ML_KEM_768).unwrap();
        let dk_bytes: [u8; KEM_DK_LEN] = key.key_bytes().unwrap().as_ref().try_into().unwrap();
        let ek = kem_ek_from_dk(&dk_bytes);

        assert_eq!(
            ek[..],
            *key.encapsulation_key()
                .unwrap()
                .key_bytes()
                .unwrap()
                .as_ref()
        );

        let restored = kem_decapsulation_key(&dk_bytes).unwrap();
        let (ciphertext, sent) = kem_encapsulate(&ek).unwrap();
        let received = kem_decapsulate(&restored, &ciphertext).unwrap();
        assert_eq!(sent.as_bytes(), received.as_bytes());
    }

    #[test]
    fn malformed_encapsulation_key_is_rejected() {
        // Every 12-bit coefficient decodes to 4095 >= q = 3329.
        assert_eq!(
            kem_encapsulate(&[0xFF; KEM_EK_LEN]).err(),
            Some(Error::BadKey)
        );
    }

    #[test]
    fn validate_rejects_inconsistent_expanded_keys() {
        let (dk, _) = kem_generate();
        assert_eq!(kem_validate_dk(&dk), Ok(()));

        let mut ek_tampered = *dk;
        ek_tampered[KEM_DK_EK_OFFSET] ^= 1;
        assert_eq!(kem_validate_dk(&ek_tampered), Err(Error::BadKey));

        // Inside dk_PKE: passes the hash check, fails the pairwise test via implicit rejection.
        let mut pke_tampered = *dk;
        pke_tampered[0] ^= 1;
        assert_eq!(kem_validate_dk(&pke_tampered), Err(Error::BadKey));
    }
}
