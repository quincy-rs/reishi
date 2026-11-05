use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
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

/// Generate a new random X25519 private key (usable as ephemeral or static).
///
/// Returns (private_key, public_key_bytes).
pub fn generate_keypair() -> Result<(PrivateKey, [u8; DH_LEN]), Error> {
    let private = PrivateKey::generate(&X25519).map_err(|_| Error::CryptoFailed)?;
    let public = public_key(&private)?;
    Ok((private, public))
}

/// Import raw 32-byte X25519 secret key material into aws-lc.
pub fn private_key(secret: &[u8; DH_LEN]) -> Result<PrivateKey, Error> {
    PrivateKey::from_private_key(&X25519, secret).map_err(|_| Error::BadKey)
}

/// Derive the 32-byte public key of an X25519 private key.
pub fn public_key(private: &PrivateKey) -> Result<[u8; DH_LEN], Error> {
    private
        .compute_public_key()
        .map_err(|_| Error::CryptoFailed)?
        .as_ref()
        .try_into()
        .map_err(|_| Error::CryptoFailed)
}

/// Perform DH with a static/ephemeral private key and a remote public key.
///
/// Returns the 32-byte shared secret, or `Error::BadKey` if the
/// result is the all-zeros point (low-order input); aws-lc rejects it.
///
/// This check is required by RFC 7748 Section 6.1 and recommended
/// by the Noise spec Section 12.1.
pub fn dh(local: &PrivateKey, remote: &[u8; DH_LEN]) -> Result<SharedSecret, Error> {
    agreement::agree(
        local,
        UnparsedPublicKey::new(&X25519, remote),
        Error::BadKey,
        |shared| {
            let mut out = [0u8; DH_LEN];
            out.copy_from_slice(shared);
            Ok(SharedSecret(out))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn reject_zero_public_key() {
        let secret = private_key(&[1u8; 32]).unwrap();
        assert_eq!(dh(&secret, &[0u8; 32]).unwrap_err(), Error::BadKey);
    }

    #[test]
    fn reject_low_order_points() {
        // Known low-order points on Curve25519; each yields an all-zero output.
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

        let secret = private_key(&[0x42u8; 32]).unwrap();
        for point in &low_order_points {
            assert_eq!(dh(&secret, point).unwrap_err(), Error::BadKey);
        }
    }

    #[test]
    fn rfc7748_shared_secret() {
        // RFC 7748 Section 6.1.
        let alice_secret =
            hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_secret = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let expected = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let alice = dh(&private_key(&alice_secret).unwrap(), &bob_public).unwrap();
        let bob = dh(&private_key(&bob_secret).unwrap(), &alice_public).unwrap();
        assert_eq!(*alice.as_bytes(), expected);
        assert_eq!(*bob.as_bytes(), expected);
    }
}
