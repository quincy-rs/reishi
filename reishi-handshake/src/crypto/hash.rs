use aws_lc_rs::{digest, hmac};
use zeroize::Zeroizing;

/// Hash output length (SHA-512 = 64 bytes).
pub const HASH_LEN: usize = 64;

/// Compute SHA-512 hash of input.
pub fn hash(input: &[u8]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(digest::digest(&digest::SHA512, input).as_ref());
    out
}

/// Compute SHA-512 hash of two concatenated inputs without allocating.
pub fn hash_two(a: &[u8], b: &[u8]) -> [u8; HASH_LEN] {
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(a);
    ctx.update(b);

    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Compute HMAC-SHA512 per [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
///
/// Accepts keys of any length; Noise keys are [`HASH_LEN`] bytes, QUIC token keys are shorter.
pub fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<[u8; HASH_LEN]> {
    hmac_multi(key, &[data])
}

/// HMAC-SHA512 over multiple data slices (fed sequentially to the MAC).
///
/// Avoids concatenating inputs into a temporary buffer.
pub(crate) fn hmac_multi(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; HASH_LEN]> {
    let key = hmac::Key::new(hmac::HMAC_SHA512, key);
    let mut ctx = hmac::Context::with_key(&key);
    for part in parts {
        ctx.update(part);
    }

    let mut result = Zeroizing::new([0u8; HASH_LEN]);
    result.copy_from_slice(ctx.sign().as_ref());
    result
}

/// HKDF with 2 output blocks, per Noise spec Section 5.3.
///
/// Returns `(output1, output2)` where:
/// - `output1 = HMAC(temp_key, 0x01)`
/// - `output2 = HMAC(temp_key, output1 || 0x02)`
pub fn hkdf2(
    chaining_key: &[u8; HASH_LEN],
    input_key_material: &[u8],
) -> (Zeroizing<[u8; HASH_LEN]>, Zeroizing<[u8; HASH_LEN]>) {
    let temp_key = hmac(chaining_key, input_key_material);
    let output1 = hmac(&temp_key[..], &[0x01]);

    let mut input2 = Zeroizing::new([0u8; HASH_LEN + 1]);
    input2[..HASH_LEN].copy_from_slice(&*output1);
    input2[HASH_LEN] = 0x02;
    let output2 = hmac(&temp_key[..], input2.as_slice());

    (output1, output2)
}

/// Three zeroized HKDF output blocks.
pub type HkdfOutput3 = (
    Zeroizing<[u8; HASH_LEN]>,
    Zeroizing<[u8; HASH_LEN]>,
    Zeroizing<[u8; HASH_LEN]>,
);

/// HKDF with 3 output blocks, used for ASK (Additional Symmetric Keys) derivation.
pub fn hkdf3(chaining_key: &[u8; HASH_LEN], input_key_material: &[u8]) -> HkdfOutput3 {
    let temp_key = hmac(chaining_key, input_key_material);

    let output1 = hmac(&temp_key[..], &[0x01]);

    let mut input2 = Zeroizing::new([0u8; HASH_LEN + 1]);
    input2[..HASH_LEN].copy_from_slice(&*output1);
    input2[HASH_LEN] = 0x02;
    let output2 = hmac(&temp_key[..], input2.as_slice());

    let mut input3 = Zeroizing::new([0u8; HASH_LEN + 1]);
    input3[..HASH_LEN].copy_from_slice(&*output2);
    input3[HASH_LEN] = 0x03;
    let output3 = hmac(&temp_key[..], input3.as_slice());

    (output1, output2, output3)
}

/// HKDF-Expand per [RFC 5869 Section 2.3](https://datatracker.ietf.org/doc/html/rfc5869#section-2.3).
///
/// Derives `output.len()` bytes from the pseudorandom key `prk` and `info`.
/// Maximum output length is 255 × [`HASH_LEN`] (16320 bytes).
///
/// Returns `true` on success, `false` if the requested length exceeds the maximum.
pub fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], output: &mut [u8]) -> bool {
    if output.is_empty() {
        return true;
    }

    let n = output.len().div_ceil(HASH_LEN);
    if n > 255 {
        return false;
    }

    let mut prev = Zeroizing::new([0u8; HASH_LEN]);
    let mut offset = 0;

    for i in 1..=n {
        // T(i) = HMAC(PRK, T(i-1) || info || i)
        let counter = [i as u8];
        prev = if i > 1 {
            hmac_multi(prk, &[&*prev, info, &counter])
        } else {
            hmac_multi(prk, &[info, &counter])
        };

        let remaining = output.len() - offset;
        let to_copy = remaining.min(HASH_LEN);
        output[offset..offset + to_copy].copy_from_slice(&prev[..to_copy]);
        offset += to_copy;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let h1 = hash(b"hello");
        let h2 = hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_different_inputs() {
        let h1 = hash(b"hello");
        let h2 = hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hmac_deterministic() {
        let key = [0x42u8; HASH_LEN];
        let h1 = hmac(&key, b"data");
        let h2 = hmac(&key, b"data");
        assert_eq!(*h1, *h2);
    }

    #[test]
    fn hash_two_equals_concatenated_hash() {
        let a = b"hello";
        let b = b"world";
        let mut combined = Vec::new();
        combined.extend_from_slice(a);
        combined.extend_from_slice(b);
        assert_eq!(hash_two(a, b), hash(&combined));
    }

    #[test]
    fn hmac_different_keys() {
        let key1 = [0x01u8; HASH_LEN];
        let key2 = [0x02u8; HASH_LEN];
        let h1 = hmac(&key1, b"data");
        let h2 = hmac(&key2, b"data");
        assert_ne!(*h1, *h2);
    }

    #[test]
    fn hmac_different_data() {
        let key = [0x42u8; HASH_LEN];
        let h1 = hmac(&key, b"data1");
        let h2 = hmac(&key, b"data2");
        assert_ne!(*h1, *h2);
    }

    #[test]
    fn hkdf2_produces_different_outputs() {
        let ck = [0x01u8; HASH_LEN];
        let (o1, o2) = hkdf2(&ck, b"ikm");
        assert_ne!(*o1, *o2);
    }

    #[test]
    fn hkdf3_produces_different_outputs() {
        let ck = [0x01u8; HASH_LEN];
        let (o1, o2, o3) = hkdf3(&ck, b"ikm");
        assert_ne!(*o1, *o2);
        assert_ne!(*o2, *o3);
        assert_ne!(*o1, *o3);
    }

    #[test]
    fn hkdf_expand_single_block() {
        let prk = [0x42u8; HASH_LEN];
        let mut out = [0u8; HASH_LEN];
        assert!(hkdf_expand(&prk, b"info", &mut out));
        // Should equal HMAC(prk, info || 0x01)
        let mut expected_input = Vec::from(b"info".as_slice());
        expected_input.push(0x01);
        assert_eq!(out, *hmac(&prk, &expected_input));
    }

    #[test]
    fn hkdf_expand_multi_block() {
        let prk = [0x42u8; HASH_LEN];
        let mut out = [0u8; HASH_LEN + 16]; // 48 bytes = 2 blocks
        assert!(hkdf_expand(&prk, b"info", &mut out));
        // First 32 bytes should match single-block output
        let mut single = [0u8; HASH_LEN];
        hkdf_expand(&prk, b"info", &mut single);
        assert_eq!(&out[..HASH_LEN], &single);
    }

    #[test]
    fn hkdf_expand_deterministic() {
        let prk = [0x42u8; HASH_LEN];
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        hkdf_expand(&prk, b"info", &mut out1);
        hkdf_expand(&prk, b"info", &mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn hkdf_expand_different_info() {
        let prk = [0x42u8; HASH_LEN];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_expand(&prk, b"info1", &mut out1);
        hkdf_expand(&prk, b"info2", &mut out2);
        assert_ne!(out1, out2);
    }

    #[test]
    fn hkdf_expand_empty_output() {
        let prk = [0u8; HASH_LEN];
        assert!(hkdf_expand(&prk, b"", &mut []));
    }
}
