use crate::MBHash;

impl MBHash {
    pub fn from_sha2_256(base: multibase::Base, hasher: sha2::Sha256) -> Self {
        use sha2::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<32>(base, ssi_multicodec::SHA2_256, &hash).unwrap()
    }
    pub fn from_sha2_384(base: multibase::Base, hasher: sha2::Sha384) -> Self {
        use sha2::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<48>(base, ssi_multicodec::SHA2_384, &hash).unwrap()
    }
    pub fn from_sha2_512(base: multibase::Base, hasher: sha2::Sha512) -> Self {
        use sha2::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<64>(base, ssi_multicodec::SHA2_512, &hash).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Base, MBHash};

    fn test_sha2_256_encode_case(base: Base) {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_sha2_256(base, hasher);
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
        let mb_hash = MBHash::from_sha2_384(base, hasher);
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
        let mb_hash = MBHash::from_sha2_512(base, hasher);
        println!("sha2_512; base: {:?}, mb_hash: {:?}", base, mb_hash);
    }

    #[test]
    fn test_sha2_512_encode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_sha2_512_encode_case(base);
        }
    }
}
