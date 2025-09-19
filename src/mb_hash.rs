use crate::{Base, MBHashStr, Multihash, Result};

/// This newtype is a String that is defined to be `multibase(base, multihash(codec, digest))`, where
/// `multihash(codec, digest)` is defined to be `varint(codec) || varint(digest.len()) || digest`.
/// See also `MBHashStr`.
///
/// References:
/// - <https://github.com/multiformats/multihash>
/// - <https://www.w3.org/TR/cid-1.0/#multihash>
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_mb_hash_str", borrow = "MBHashStr")]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MBHash(String);

impl MBHash {
    pub fn from_multihash<const SIZE: usize>(
        base: Base,
        multihash: Multihash<SIZE>,
    ) -> Result<Self> {
        Ok(Self(multibase::encode(base, multihash.to_bytes())))
    }
    pub fn encoded<const SIZE: usize>(
        base: Base,
        codec: u64,
        digest_byte_v: &[u8],
    ) -> Result<Self> {
        let multihash = multihash::Multihash::<SIZE>::wrap(codec, digest_byte_v)?;
        Self::from_multihash(base, multihash)
    }
}

impl From<MBHash> for String {
    fn from(mb_hash: MBHash) -> Self {
        mb_hash.0
    }
}

#[cfg(test)]
mod tests {
    use crate::MBHash;

    use super::*;

    #[test]
    fn test_mb_hash_roundtrip() {
        let base_v = [
            Base::Base64Url,
            Base::Base64,
            Base::Base58Btc,
            Base::Base32HexLower,
            Base::Base32HexUpper,
        ];
        let test_case_v = [
            (ssi_multicodec::BLAKE3, vec![0u8; 32]),
            (ssi_multicodec::SHA2_256, vec![0u8; 32]),
            (ssi_multicodec::SHA3_256, vec![0u8; 32]),
            (ssi_multicodec::SHA3_512, vec![0u8; 64]),
        ];

        for base in base_v {
            for (codec, digest_byte_v) in test_case_v.iter() {
                let codec = *codec;
                let mb_hash = MBHash::encoded::<64>(base, codec, digest_byte_v).expect("pass");
                let multihash = mb_hash.decoded::<64>().expect("pass");
                assert_eq!(multihash.code(), codec);
                assert_eq!(multihash.size() as usize, digest_byte_v.len());
                assert_eq!(multihash.digest(), digest_byte_v);
            }
        }
    }
}
