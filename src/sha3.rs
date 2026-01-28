use crate::MBHash;

impl MBHash {
    pub fn from_sha3_224(base: multibase::Base, hasher: sha3::Sha3_224) -> Self {
        use sha3::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<28>(base, ssi_multicodec::SHA3_224, &hash).unwrap()
    }
    pub fn from_sha3_256(base: multibase::Base, hasher: sha3::Sha3_256) -> Self {
        use sha3::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<32>(base, ssi_multicodec::SHA3_256, &hash).unwrap()
    }
    pub fn from_sha3_384(base: multibase::Base, hasher: sha3::Sha3_384) -> Self {
        use sha3::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<48>(base, ssi_multicodec::SHA3_384, &hash).unwrap()
    }
    pub fn from_sha3_512(base: multibase::Base, hasher: sha3::Sha3_512) -> Self {
        use sha3::Digest;
        let hash = hasher.finalize();
        MBHash::encoded::<64>(base, ssi_multicodec::SHA3_512, &hash).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Base, MBHash};

    fn test_sha3_224_encode_case(base: Base) {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_224::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_sha3_224(base, hasher);
        println!("sha3_224; base: {:?}, mb_hash: {:?}", base, mb_hash);
    }

    #[test]
    fn test_sha3_224_encode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_sha3_224_encode_case(base);
        }
    }

    fn test_sha3_256_encode_case(base: Base) {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_256::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_sha3_256(base, hasher);
        println!("sha3_256; base: {:?}, mb_hash: {:?}", base, mb_hash);
    }

    #[test]
    fn test_sha3_256_encode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_sha3_256_encode_case(base);
        }
    }

    fn test_sha3_384_encode_case(base: Base) {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_384::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_sha3_384(base, hasher);
        println!("sha3_384; base: {:?}, mb_hash: {:?}", base, mb_hash);
    }

    #[test]
    fn test_sha3_384_encode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_sha3_384_encode_case(base);
        }
    }

    fn test_sha3_512_encode_case(base: Base) {
        use sha3::Digest;
        let mut hasher = sha3::Sha3_512::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_sha3_512(base, hasher);
        println!("sha3_512; base: {:?}, mb_hash: {:?}", base, mb_hash);
    }

    #[test]
    fn test_sha3_512_encode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_sha3_512_encode_case(base);
        }
    }
}
