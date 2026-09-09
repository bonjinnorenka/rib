use oci_spec::image::Digest;
use sha2::{Digest as _, Sha256};

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    finish_sha256(hasher)
}

pub fn finish_sha256(hasher: Sha256) -> Digest {
    format!("sha256:{}", hex::encode(hasher.finalize()))
        .parse()
        .expect("SHA-256 always produces a valid OCI digest")
}

pub fn blob_path(digest: &Digest) -> String {
    format!("blobs/{}/{}", digest.algorithm(), digest.digest())
}

pub fn short_digest(digest: &Digest) -> &str {
    digest.digest().get(..12).unwrap_or_else(|| digest.digest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::image::DigestAlgorithm;

    #[test]
    fn empty_input_has_known_digest() {
        assert_eq!(
            sha256_digest(b"").to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn blob_path_preserves_algorithm() {
        let digest: Digest = format!("sha512:{}", "a".repeat(128)).parse().unwrap();
        assert_eq!(digest.algorithm(), &DigestAlgorithm::Sha512);
        assert_eq!(
            blob_path(&digest),
            format!("blobs/sha512/{}", "a".repeat(128))
        );
    }
}
