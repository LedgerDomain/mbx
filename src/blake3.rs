use crate::{Base, MBHash};

impl MBHash {
    pub fn from_blake3(base: Base, hasher: blake3::Hasher) -> Self {
        let digest = hasher.finalize();
        MBHash::encoded::<32>(base, ssi_multicodec::BLAKE3, digest.as_bytes().as_slice()).unwrap()
    }
}

// TODO: Conversions back to blake3::Hasher?

#[cfg(test)]
mod tests {
    use crate::{Base, MBHash};

    fn test_blake3_encode_case(base: Base) {
        let mut hasher = blake3::Hasher::new();
        use std::io::Write;
        hasher.write_all(b"HIPPO").unwrap();
        let mb_hash = MBHash::from_blake3(base, hasher);
        println!("blake3 mb_hash: {:?}", mb_hash);
    }

    #[test]
    fn test_blake3_encode_0() {
        test_blake3_encode_case(Base::Base32Lower);
        test_blake3_encode_case(Base::Base58Btc);
        test_blake3_encode_case(Base::Base64Url);
    }
}
