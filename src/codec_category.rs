#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CodecCategory {
    /// Multihash hash functions are cryptographic hash functions.
    Multihash,
    /// Private key
    PrivKey,
    /// Public key
    PubKey,
    /// Signature
    Signature,
    /// Symmetric key
    SymmetricKey,
    /// The codec is not handled here, but it could still be a valid codec.
    Unspecified,
}

impl CodecCategory {
    pub fn from_codec(codec: u64) -> Self {
        match codec {
            // Multihash
            ssi_multicodec::IDENTITY => Self::Multihash,
            codec if codec >= ssi_multicodec::SHA1 && codec <= ssi_multicodec::BLAKE3 => {
                Self::Multihash
            }
            ssi_multicodec::SHA2_384 => Self::Multihash,
            ssi_multicodec::DBL_SHA2_256 | ssi_multicodec::MD4 | ssi_multicodec::MD5 => {
                Self::Multihash
            }
            codec
                if codec >= ssi_multicodec::SHA2_256_TRUNC254_PADDED
                    && codec <= ssi_multicodec::SHA2_512_256 =>
            {
                Self::Multihash
            }
            codec if codec >= ssi_multicodec::RIPEMD_128 && codec <= ssi_multicodec::RIPEMD_320 => {
                Self::Multihash
            }
            ssi_multicodec::X11 | ssi_multicodec::KANGAROOTWELVE | ssi_multicodec::SM3_256 => {
                Self::Multihash
            }
            codec if codec >= ssi_multicodec::BLAKE2B_8 && codec <= ssi_multicodec::BLAKE2S_256 => {
                Self::Multihash
            }
            codec
                if codec >= ssi_multicodec::SKEIN256_8
                    && codec <= ssi_multicodec::SKEIN1024_1024 =>
            {
                Self::Multihash
            }
            // PrivKey
            codec
                if codec >= ssi_multicodec::ED25519_PRIV && codec <= ssi_multicodec::P521_PRIV =>
            {
                Self::PrivKey
            }
            // PubKey
            ssi_multicodec::SECP256K1_PUB => Self::PubKey,
            codec
                if codec >= ssi_multicodec::BLS12_381_G1_PUB
                    && codec <= ssi_multicodec::SR25519_PUB =>
            {
                Self::PubKey
            }
            codec if codec >= ssi_multicodec::P256_PUB && codec <= ssi_multicodec::SM2_PUB => {
                Self::PubKey
            }
            ssi_multicodec::JWK_JCS_PUB => Self::PubKey,
            // SymmetricKey
            ssi_multicodec::AES_128
            | ssi_multicodec::AES_192
            | ssi_multicodec::AES_256
            | ssi_multicodec::CHACHA_128
            | ssi_multicodec::CHACHA_256 => Self::SymmetricKey,
            // Signature
            ssi_multicodec::ES256K
            | ssi_multicodec::BLS_12381_G1_SIG
            | ssi_multicodec::BLS_12381_G2_SIG
            | ssi_multicodec::EDDSA
            | ssi_multicodec::EIP_191
            | ssi_multicodec::ES256
            // NOTE: This is a typo in the multicodec table.  It should be ES384.
            | ssi_multicodec::ES284
            | ssi_multicodec::ES512
            | ssi_multicodec::RS256 => Self::Signature,
            _ => Self::Unspecified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_category() {
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::SHA2_256),
            CodecCategory::Multihash
        );
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::SHA2_384),
            CodecCategory::Multihash
        );
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::SHA2_512),
            CodecCategory::Multihash
        );
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::SHA3_256),
            CodecCategory::Multihash
        );
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::SHA3_512),
            CodecCategory::Multihash
        );
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::BLAKE3),
            CodecCategory::Multihash
        );

        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::ED25519_PRIV),
            CodecCategory::PrivKey
        );
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::P256_PRIV),
            CodecCategory::PrivKey
        );
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::P384_PRIV),
            CodecCategory::PrivKey
        );
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::P521_PRIV),
            CodecCategory::PrivKey
        );
        assert_eq!(
            CodecCategory::from_codec(ssi_multicodec::SECP256K1_PRIV),
            CodecCategory::PrivKey
        );
    }
}
