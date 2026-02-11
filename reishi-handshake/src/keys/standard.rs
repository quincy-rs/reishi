use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekStaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An X25519 static secret key.
///
/// Zeroized from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StaticSecret(DalekStaticSecret);

impl StaticSecret {
    /// Create from raw 32-byte secret key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(DalekStaticSecret::from(bytes))
    }

    /// Wrap an existing `DalekStaticSecret`.
    pub(crate) fn from_dalek(secret: DalekStaticSecret) -> Self {
        Self(secret)
    }

    /// Export the raw 32-byte secret key material.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn inner(&self) -> &DalekStaticSecret {
        &self.0
    }
}

/// An X25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// The length of a public key in bytes.
    pub const LEN: usize = 32;

    /// Create from raw 32-byte public key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the raw bytes of this public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey({:02x?})", &self.0[..4])
    }
}

/// A keypair consisting of a static secret and its corresponding public key.
pub struct KeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a new random keypair using the provided RNG.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let secret = DalekStaticSecret::random_from_rng(rng);
        let public = DalekPublicKey::from(&secret);
        Self {
            secret: StaticSecret(secret),
            public: PublicKey(public.to_bytes()),
        }
    }

    /// Create a keypair from an existing static secret.
    pub fn from_secret(secret: StaticSecret) -> Self {
        let public = DalekPublicKey::from(secret.inner());
        Self {
            secret,
            public: PublicKey(public.to_bytes()),
        }
    }

    /// Create a keypair from raw 32-byte secret key material.
    ///
    /// Derives the corresponding public key automatically.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self::from_secret(StaticSecret::from_bytes(bytes))
    }

    /// Export the raw 32-byte secret key material.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_secret_bytes_matches_manual_construction() {
        let bytes = [42u8; 32];

        let from_helper = KeyPair::from_secret_bytes(bytes);

        let secret = DalekStaticSecret::from(bytes);
        let public = DalekPublicKey::from(&secret);
        let manual = KeyPair {
            secret: StaticSecret(secret),
            public: PublicKey(public.to_bytes()),
        };

        assert_eq!(from_helper.public.as_bytes(), manual.public.as_bytes());
    }

    #[test]
    fn from_secret_derives_correct_public_key() {
        let bytes = [42u8; 32];
        let secret = StaticSecret::from_bytes(bytes);
        let expected_public = DalekPublicKey::from(&DalekStaticSecret::from(bytes)).to_bytes();

        let kp = KeyPair::from_secret(secret);

        assert_eq!(*kp.public.as_bytes(), expected_public);
    }

    #[test]
    fn secret_bytes_round_trips() {
        let bytes = [42u8; 32];
        let kp = KeyPair::from_secret_bytes(bytes);

        assert_eq!(kp.secret_bytes(), bytes);
    }
}
