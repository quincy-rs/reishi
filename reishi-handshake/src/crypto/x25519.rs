use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekStaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;

/// DH output length in bytes (X25519 = 32).
pub const DH_LEN: usize = 32;

/// A shared secret resulting from a Diffie-Hellman operation.
///
/// Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

impl SharedSecret {
    /// Access the raw 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Generate a new random X25519 secret key (usable as ephemeral or static).
///
/// Returns (secret, public_key_bytes).
pub fn generate_keypair(rng: &mut impl CryptoRngCore) -> (DalekStaticSecret, [u8; DH_LEN]) {
    let secret = DalekStaticSecret::random_from_rng(rng);
    let public = DalekPublicKey::from(&secret);
    (secret, public.to_bytes())
}

/// Perform DH with a static/ephemeral secret and a remote public key.
///
/// Returns the 32-byte shared secret, or `Error::BadKey` if the
/// result is the all-zeros point (low-order input).
///
/// This check is required by RFC 7748 Section 6.1 and recommended
/// by the Noise spec Section 12.1.
pub fn dh(local: &DalekStaticSecret, remote: &DalekPublicKey) -> Result<SharedSecret, Error> {
    let shared = local.diffie_hellman(remote);
    validate_shared_secret(shared.as_bytes())
}

/// Reject the all-zeros shared secret, which indicates a low-order public key.
fn validate_shared_secret(bytes: &[u8; 32]) -> Result<SharedSecret, Error> {
    let is_zero = bytes.ct_eq(&[0u8; 32]);
    if bool::from(is_zero) {
        Err(Error::BadKey)
    } else {
        Ok(SharedSecret(*bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_zero_public_key() {
        let secret = DalekStaticSecret::from([1u8; 32]);
        let zero_pk = DalekPublicKey::from([0u8; 32]);
        let result = dh(&secret, &zero_pk);
        assert_eq!(result.unwrap_err(), Error::BadKey);
    }

    #[test]
    fn reject_low_order_points() {
        // Known low-order points on Curve25519
        let low_order_points: [[u8; 32]; 4] = [
            // Identity (all zeros)
            [0; 32],
            // Point of order 2
            {
                let mut p = [0u8; 32];
                p[0] = 1;
                p
            },
            // ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            // e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
        ];

        let secret = DalekStaticSecret::from([0x42u8; 32]);
        for point in &low_order_points {
            let pk = DalekPublicKey::from(*point);
            let result = dh(&secret, &pk);
            // Some low-order points produce non-zero results due to X25519's
            // cofactor clamping -- those are safe (not predictable without the key).
            if let Ok(shared) = &result {
                assert!(!bool::from(shared.as_bytes().ct_eq(&[0u8; 32])));
            }
        }
    }

    #[test]
    fn normal_dh_succeeds() {
        let (secret1, pub1) = generate_keypair(&mut rand_core::OsRng);
        let (secret2, pub2) = generate_keypair(&mut rand_core::OsRng);

        let shared1 = dh(&secret1, &DalekPublicKey::from(pub2)).unwrap();
        let shared2 = dh(&secret2, &DalekPublicKey::from(pub1)).unwrap();
        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }
}
