//! Static key types for the KEM-only `pqIK` and hybrid IK handshakes.
//!
//! KEM-only secrets serialize as the 2400-byte FIPS 203 expanded ML-KEM-768
//! decapsulation key. Hybrid secrets prepend the X25519 secret. Restoring a
//! secret validates the expanded key's internal consistency.

use core::hash::{Hash, Hasher};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::standard::{KeyPair, PublicKey, StaticSecret};
use crate::crypto::pq::{KEM_DK_LEN, KEM_EK_LEN, kem_ek_from_dk, kem_generate, kem_validate_dk};
use crate::error::Error;

/// An ML-KEM-768 encapsulation key.
#[derive(Clone)]
pub struct EncapsulationKey([u8; Self::LEN]);

impl EncapsulationKey {
    /// Serialized length of an ML-KEM-768 encapsulation key.
    pub const LEN: usize = KEM_EK_LEN;

    /// Construct an encapsulation key from its fixed-width wire encoding.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width wire encoding of this encapsulation key.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl AsRef<[u8; Self::LEN]> for EncapsulationKey {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl AsRef<[u8]> for EncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for EncapsulationKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for EncapsulationKey {}

impl Hash for EncapsulationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl core::fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "EncapsulationKey([{:02x}{:02x}..{}B])",
            self.0[0],
            self.0[1],
            Self::LEN,
        )
    }
}

impl Drop for EncapsulationKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// KEM-only static secret: the FIPS 203 expanded ML-KEM-768 decapsulation key.
pub struct PqStaticSecret {
    /// Expanded ML-KEM decapsulation key (`dk_PKE || ek || H(ek) || z`).
    pub(crate) kem_dk: Zeroizing<[u8; KEM_DK_LEN]>,
}

impl PqStaticSecret {
    /// Serialized length of the expanded ML-KEM decapsulation key.
    pub const LEN: usize = KEM_DK_LEN;
}

/// KEM-only ML-KEM-768 public key.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PqPublicKey {
    /// ML-KEM-768 encapsulation key used by the remote peer.
    pub(crate) kem_ek: EncapsulationKey,
}

impl PqPublicKey {
    /// Serialized length of a KEM-only public key.
    pub const LEN: usize = EncapsulationKey::LEN;

    /// Borrow the ML-KEM-768 encapsulation key.
    pub fn kem_ek(&self) -> &EncapsulationKey {
        &self.kem_ek
    }

    /// Construct a KEM-only public key from its wire encoding.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self {
            kem_ek: EncapsulationKey::from_bytes(bytes),
        }
    }

    /// Serialize this KEM-only public key for storage or transport.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        *self.kem_ek.as_bytes()
    }
}

/// KEM-only static keypair for `pqIK`.
pub struct PqKeyPair {
    /// Secret expanded ML-KEM decapsulation key.
    pub secret: PqStaticSecret,

    /// Corresponding ML-KEM encapsulation key.
    pub public: PqPublicKey,
}

impl PqKeyPair {
    /// Generate a KEM-only static keypair from aws-lc's CSPRNG.
    pub fn generate() -> Self {
        let (kem_dk, kem_ek) = kem_generate();

        Self {
            secret: PqStaticSecret { kem_dk },

            public: PqPublicKey {
                kem_ek: EncapsulationKey::from_bytes(kem_ek),
            },
        }
    }

    /// Reconstruct the public key belonging to an existing static secret.
    pub fn from_secret(secret: PqStaticSecret) -> Self {
        let kem_ek = kem_ek_from_dk(&secret.kem_dk);

        Self {
            secret,

            public: PqPublicKey {
                kem_ek: EncapsulationKey::from_bytes(kem_ek),
            },
        }
    }

    /// Restore a keypair from an expanded ML-KEM decapsulation key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadKey`] if the key fails the FIPS 203 hash check or a
    /// pairwise consistency test (corrupted or mismatched key material).
    pub fn from_secret_bytes(bytes: &[u8; PqStaticSecret::LEN]) -> Result<Self, Error> {
        kem_validate_dk(bytes)?;

        Ok(Self::from_secret(PqStaticSecret {
            kem_dk: Zeroizing::new(*bytes),
        }))
    }

    /// Export the expanded ML-KEM decapsulation key in zeroizing storage.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; PqStaticSecret::LEN]> {
        self.secret.kem_dk.clone()
    }
}

/// Hybrid X25519 + ML-KEM static secret.
pub struct HybridStaticSecret {
    /// X25519 static secret used by the classical IK tokens.
    pub(crate) dh: StaticSecret,

    /// Expanded ML-KEM decapsulation key (`dk_PKE || ek || H(ek) || z`).
    pub(crate) kem_dk: Zeroizing<[u8; KEM_DK_LEN]>,
}

impl HybridStaticSecret {
    /// Serialized length of `x25519_secret || ml_kem_expanded_dk`.
    pub const LEN: usize = StaticSecret::LEN + KEM_DK_LEN;
}

/// Hybrid X25519 + ML-KEM public key.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct HybridPublicKey {
    /// X25519 public key used by the classical IK tokens.
    pub(crate) dh: PublicKey,

    /// ML-KEM-768 encapsulation key used by the pqIK tokens.
    pub(crate) kem_ek: EncapsulationKey,
}

impl HybridPublicKey {
    /// Serialized length of `x25519_public || ml_kem_encapsulation_key`.
    pub const LEN: usize = PublicKey::LEN + EncapsulationKey::LEN;

    /// Borrow the X25519 component of this hybrid public key.
    pub fn dh_public(&self) -> &PublicKey {
        &self.dh
    }

    /// Borrow the ML-KEM component of this hybrid public key.
    pub fn kem_ek(&self) -> &EncapsulationKey {
        &self.kem_ek
    }

    /// Parse `x25519_public || ml_kem_encapsulation_key`.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        let mut dh_public = [0u8; PublicKey::LEN];
        dh_public.copy_from_slice(&bytes[..PublicKey::LEN]);

        let mut kem_public = [0u8; EncapsulationKey::LEN];
        kem_public.copy_from_slice(&bytes[PublicKey::LEN..]);

        Self {
            dh: PublicKey::from_bytes(dh_public),
            kem_ek: EncapsulationKey::from_bytes(kem_public),
        }
    }

    /// Serialize `x25519_public || ml_kem_encapsulation_key`.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut public_bytes = [0u8; Self::LEN];

        public_bytes[..PublicKey::LEN].copy_from_slice(self.dh.as_bytes());
        public_bytes[PublicKey::LEN..].copy_from_slice(self.kem_ek.as_bytes());

        public_bytes
    }
}

/// Hybrid X25519 + ML-KEM static keypair.
pub struct HybridKeyPair {
    /// X25519 secret and expanded ML-KEM decapsulation key.
    pub secret: HybridStaticSecret,

    /// Corresponding X25519 and ML-KEM public keys.
    pub public: HybridPublicKey,
}

impl HybridKeyPair {
    /// Generate independent X25519 and ML-KEM key material from aws-lc's CSPRNG.
    pub fn generate() -> Self {
        let dh_keypair = KeyPair::generate();
        let (kem_dk, kem_ek) = kem_generate();

        Self {
            secret: HybridStaticSecret {
                dh: dh_keypair.secret,
                kem_dk,
            },

            public: HybridPublicKey {
                dh: dh_keypair.public,
                kem_ek: EncapsulationKey::from_bytes(kem_ek),
            },
        }
    }

    /// Reconstruct both public-key components from an existing hybrid secret.
    pub fn from_secret(secret: HybridStaticSecret) -> Self {
        let dh_keypair = KeyPair::from_secret(secret.dh);
        let kem_ek = kem_ek_from_dk(&secret.kem_dk);

        Self {
            secret: HybridStaticSecret {
                dh: dh_keypair.secret,
                kem_dk: secret.kem_dk,
            },

            public: HybridPublicKey {
                dh: dh_keypair.public,
                kem_ek: EncapsulationKey::from_bytes(kem_ek),
            },
        }
    }

    /// Restore a keypair from `x25519_secret || ml_kem_expanded_dk`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadKey`] if the ML-KEM part fails the FIPS 203 hash
    /// check or a pairwise consistency test. Any 32 bytes are a valid X25519 secret.
    pub fn from_secret_bytes(bytes: &[u8; HybridStaticSecret::LEN]) -> Result<Self, Error> {
        let (dh_secret, kem_bytes) = bytes.split_at(StaticSecret::LEN);

        let mut kem_dk = Zeroizing::new([0u8; KEM_DK_LEN]);
        kem_dk.copy_from_slice(kem_bytes);
        kem_validate_dk(&kem_dk)?;

        Ok(Self::from_secret(HybridStaticSecret {
            dh: StaticSecret::from_bytes(
                dh_secret
                    .try_into()
                    .expect("prefix is StaticSecret::LEN bytes"),
            ),
            kem_dk,
        }))
    }

    /// Export `x25519_secret || ml_kem_expanded_dk` in zeroizing storage.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; HybridStaticSecret::LEN]> {
        let mut secret_bytes = Zeroizing::new([0u8; HybridStaticSecret::LEN]);

        secret_bytes[..StaticSecret::LEN].copy_from_slice(&*self.secret.dh.to_bytes());
        secret_bytes[StaticSecret::LEN..].copy_from_slice(&*self.secret.kem_dk);

        secret_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_secret_and_public_round_trip() {
        let keypair = PqKeyPair::generate();
        let restored = PqKeyPair::from_secret_bytes(&keypair.secret_bytes()).unwrap();

        assert_eq!(keypair.public, restored.public);
        assert_eq!(PqStaticSecret::LEN, 2400);
        assert_eq!(PqPublicKey::LEN, 1184);
    }

    #[test]
    fn hybrid_secret_and_public_round_trip() {
        let keypair = HybridKeyPair::generate();
        let restored = HybridKeyPair::from_secret_bytes(&keypair.secret_bytes()).unwrap();

        assert_eq!(keypair.public, restored.public);
        assert_eq!(HybridStaticSecret::LEN, 2432);
        assert_eq!(HybridPublicKey::LEN, 1216);
    }

    #[test]
    fn tampered_secret_bytes_are_rejected() {
        let mut pq = PqKeyPair::generate().secret_bytes();
        pq[1152] ^= 1;
        assert_eq!(PqKeyPair::from_secret_bytes(&pq).err(), Some(Error::BadKey));

        let mut hybrid = HybridKeyPair::generate().secret_bytes();
        hybrid[StaticSecret::LEN + 1152] ^= 1;
        assert_eq!(
            HybridKeyPair::from_secret_bytes(&hybrid).err(),
            Some(Error::BadKey)
        );
    }

    #[test]
    fn public_serialization_round_trips() {
        let pq = PqKeyPair::generate();
        assert_eq!(PqPublicKey::from_bytes(pq.public.to_bytes()), pq.public);

        let hybrid = HybridKeyPair::generate();
        assert_eq!(
            HybridPublicKey::from_bytes(hybrid.public.to_bytes()),
            hybrid.public,
        );
    }
}
