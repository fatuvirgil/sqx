//! MinHash Baseline Engine
//!
//! Provides stable similarity estimation using locality-sensitive hashing.
//! Resilient to dynamic noise (CSRF tokens, timestamps, IDs).

/// Generate character k-shingles from normalized text.
pub fn char_shingles(s: &str, k: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < k {
        return vec![s.to_string()];
    }
    chars.windows(k).map(|w| w.iter().collect()).collect()
}

/// Compute MinHash signature using a simple family of hash functions.
/// `num_hashes` controls the signature size (accuracy vs speed trade-off).
pub fn compute_minhash(body: &str, k: usize, num_hashes: usize) -> Vec<u64> {
    let norm = normalize_for_hashing(body);
    let shingles = char_shingles(&norm, k);
    if shingles.is_empty() {
        return vec![0u64; num_hashes];
    }

    let mut sig = Vec::with_capacity(num_hashes);
    for i in 0..num_hashes {
        let mut min_val = u64::MAX;
        let seed = (i + 1) as u64;
        for s in &shingles {
            // FNV-1a style hash with per-hash offset
            let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
            for b in s.bytes() {
                hash ^= (b as u64).wrapping_add(seed);
                hash = hash.wrapping_mul(0x100000001b3); // FNV prime
            }
            if hash < min_val {
                min_val = hash;
            }
        }
        sig.push(min_val);
    }
    sig
}

/// Estimate Jaccard similarity from two MinHash signatures.
pub fn minhash_jaccard(a: &[u64], b: &[u64]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    matches as f32 / a.len() as f32
}

/// Lightweight normalization for hashing purposes.
fn normalize_for_hashing(body: &str) -> String {
    body.chars()
        .filter(|c| c.is_ascii_alphanumeric() || c.is_whitespace())
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shingles_basic() {
        let s = "hello";
        let sh = char_shingles(s, 3);
        assert_eq!(sh.len(), 3);
        assert_eq!(sh[0], "hel");
        assert_eq!(sh[1], "ell");
        assert_eq!(sh[2], "llo");
    }

    #[test]
    fn shingles_short_input() {
        let s = "ab";
        let sh = char_shingles(s, 3);
        assert_eq!(sh, vec!["ab"]);
    }

    #[test]
    fn minhash_deterministic() {
        let body = "hello world";
        let sig1 = compute_minhash(body, 4, 64);
        let sig2 = compute_minhash(body, 4, 64);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn minhash_similarity_high_for_similar() {
        let a = "hello world this is a test";
        let b = "hello world this is a test!";
        let sig_a = compute_minhash(a, 4, 64);
        let sig_b = compute_minhash(b, 4, 64);
        let sim = minhash_jaccard(&sig_a, &sig_b);
        assert!(sim > 0.8, "expected high similarity, got {}", sim);
    }

    #[test]
    fn minhash_similarity_low_for_different() {
        let a = "hello world";
        let b = "completely different text here";
        let sig_a = compute_minhash(a, 4, 64);
        let sig_b = compute_minhash(b, 4, 64);
        let sim = minhash_jaccard(&sig_a, &sig_b);
        assert!(sim < 0.5, "expected low similarity, got {}", sim);
    }
}
