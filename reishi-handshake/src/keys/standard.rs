use core::hash::{Hash, Hasher};

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekStaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An X25519 static secret key.
///
/// Zeroized from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StaticSecret(DalekStaticSecret);

impl StaticSecret {
    /// The length of a static secret key in bytes.
    pub const LEN: usize = 32;

    /// Create from raw 32-byte secret key material.
    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Self {
        let mut copy = *bytes;
        // DalekStaticSecret::from takes [u8; 32] by value, so a by-value copy
        // lands on its stack frame. We cannot zeroize that copy, but it lives in
        // dead stack space once the call returns and is quickly overwritten.
        let secret = Self(DalekStaticSecret::from(copy));
        copy.zeroize();
        secret
    }

    /// Wrap an existing `DalekStaticSecret`.
    pub(crate) fn from_dalek(secret: DalekStaticSecret) -> Self {
        Self(secret)
    }

    /// Export the raw 32-byte secret key material.
    pub fn to_bytes(&self) -> Zeroizing<[u8; Self::LEN]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub(crate) fn inner(&self) -> &DalekStaticSecret {
        &self.0
    }
}

/// An X25519 public key (32 bytes).
#[derive(Clone, Copy)]
pub struct PublicKey([u8; Self::LEN]);

impl PublicKey {
    /// The length of a public key in bytes.
    pub const LEN: usize = 32;

    /// Create from raw 32-byte public key.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Access the raw bytes of this public key.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl AsRef<[u8; Self::LEN]> for PublicKey {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
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
    pub fn from_secret_bytes(bytes: &[u8; StaticSecret::LEN]) -> Self {
        Self::from_secret(StaticSecret::from_bytes(bytes))
    }

    /// Export the raw 32-byte secret key material.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; StaticSecret::LEN]> {
        self.secret.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_secret_bytes_matches_manual_construction() {
        let bytes = [42u8; 32];

        let from_helper = KeyPair::from_secret_bytes(&bytes);

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
        let secret = StaticSecret::from_bytes(&bytes);
        let expected_public = DalekPublicKey::from(&DalekStaticSecret::from(bytes)).to_bytes();

        let kp = KeyPair::from_secret(secret);

        assert_eq!(*kp.public.as_bytes(), expected_public);
    }

    #[test]
    fn secret_bytes_round_trips() {
        let bytes = [42u8; 32];
        let kp = KeyPair::from_secret_bytes(&bytes);

        assert_eq!(*kp.secret_bytes(), bytes);
    }

    #[test]
    fn public_key_as_ref_array() {
        let bytes = [7u8; PublicKey::LEN];
        let pk = PublicKey::from_bytes(bytes);
        let r: &[u8; PublicKey::LEN] = pk.as_ref();
        assert_eq!(*r, bytes);
    }

    #[test]
    fn public_key_as_ref_slice() {
        let bytes = [7u8; PublicKey::LEN];
        let pk = PublicKey::from_bytes(bytes);
        let r: &[u8] = pk.as_ref();
        assert_eq!(r, &bytes);
    }

    #[test]
    fn public_key_from_bytes_as_bytes_round_trip() {
        let bytes = [99u8; PublicKey::LEN];
        let pk = PublicKey::from_bytes(bytes);
        assert_eq!(*pk.as_bytes(), bytes);
    }

    #[test]
    fn public_key_equality_constant_time() {
        let a = PublicKey::from_bytes([1u8; PublicKey::LEN]);
        let b = PublicKey::from_bytes([1u8; PublicKey::LEN]);
        let c = PublicKey::from_bytes([2u8; PublicKey::LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn public_key_debug_does_not_leak_full_key() {
        let pk = PublicKey::from_bytes([0xab; PublicKey::LEN]);
        let dbg = format!("{:?}", pk);
        assert!(dbg.starts_with("PublicKey("));
        // Only first 4 bytes shown
        assert!(!dbg.contains(&format!("{:02x?}", &[0xabu8; PublicKey::LEN][..])));
    }
}
