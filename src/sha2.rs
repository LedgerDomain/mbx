use crate::MBHash;

impl MBHash {
    /// Construct an MBHash from a SHA-224 hash value (part of the SHA-2 family of hash functions).
    pub fn from_sha224(base: multibase::Base, hasher: sha2::Sha224) -> Self {
        use sha2::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<28>(base, ssi_multicodec::SHA2_224, &hash).unwrap()
    }
    /// Construct an MBHash from a SHA-256 hash value (part of the SHA-2 family of hash functions).
    pub fn from_sha256(base: multibase::Base, hasher: sha2::Sha256) -> Self {
        use sha2::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<32>(base, ssi_multicodec::SHA2_256, &hash).unwrap()
    }
    /// Construct an MBHash from a SHA-384 hash value (part of the SHA-2 family of hash functions).
    pub fn from_sha384(base: multibase::Base, hasher: sha2::Sha384) -> Self {
        use sha2::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<48>(base, ssi_multicodec::SHA2_384, &hash).unwrap()
    }
    /// Construct an MBHash from a SHA-512 hash value (part of the SHA-2 family of hash functions).
    pub fn from_sha512(base: multibase::Base, hasher: sha2::Sha512) -> Self {
        use sha2::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<64>(base, ssi_multicodec::SHA2_512, &hash).unwrap()
    }
    /// Construct an MBHash from a SHA-224 hash value (part of the SHA-2 family of hash functions).
    #[deprecated(since = "0.1.0", note = "Use `MBHash::from_sha256` instead")]
    pub fn from_sha2_256(base: multibase::Base, hasher: sha2::Sha256) -> Self {
        Self::from_sha256(base, hasher)
    }
    /// Construct an MBHash from a SHA-512 hash value (part of the SHA-2 family of hash functions).
    #[deprecated(since = "0.1.0", note = "Use `MBHash::from_sha512` instead")]
    pub fn from_sha2_512(base: multibase::Base, hasher: sha2::Sha512) -> Self {
        Self::from_sha512(base, hasher)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Base, MBHash};

    fn test_sha2_224_encode_case(base: Base) {
        use sha2::Digest;
        let mut hasher = sha2::Sha224::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_sha224(base, hasher);
        println!("sha2_224; base: {:?}, mb_hash: {:?}", base, mb_hash);
    }

    #[test]
    fn test_sha2_224_encode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_sha2_224_encode_case(base);
        }
    }

    fn test_sha2_256_encode_case(base: Base) {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_sha256(base, hasher);
        println!("sha2_256; base: {:?}, mb_hash: {:?}", base, mb_hash);
    }

    #[test]
    fn test_sha2_256_encode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_sha2_256_encode_case(base);
        }
    }

    fn test_sha2_384_encode_case(base: Base) {
        use sha2::Digest;
        let mut hasher = sha2::Sha384::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_sha384(base, hasher);
        println!("sha2_384; base: {:?}, mb_hash: {:?}", base, mb_hash);
    }

    #[test]
    fn test_sha2_384_encode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_sha2_384_encode_case(base);
        }
    }

    fn test_sha2_512_encode_case(base: Base) {
        use sha2::Digest;
        let mut hasher = sha2::Sha512::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_sha512(base, hasher);
        println!("sha2_512; base: {:?}, mb_hash: {:?}", base, mb_hash);
    }

    #[test]
    fn test_sha2_512_encode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_sha2_512_encode_case(base);
        }
    }
}
