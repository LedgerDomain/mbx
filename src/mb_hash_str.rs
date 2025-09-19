use crate::{Base, CodecCategory, Error, Multihash, ensure};

/// This newtype is a str that is defined to be `multibase(base, multihash(codec, digest))`, where
/// `multihash(codec, digest)` is defined to be `varint(codec) || varint(digest.len()) || digest`.
/// See also `MBHash`.
///
/// References:
/// - <https://github.com/multiformats/multihash>
/// - <https://www.w3.org/TR/cid-1.0/#multihash>
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", pneu_str(deserialize, serialize))]
#[repr(transparent)]
pub struct MBHashStr(str);

impl MBHashStr {
    /// Returns the base of this MBHashStr.
    pub fn base(&self) -> Base {
        Base::from_code(self.base_char()).expect("programmer error")
    }
    /// Returns the base character of this MBHashStr.
    pub fn base_char(&self) -> char {
        self.0.chars().next().expect("programmer error")
    }
    /// Decodes this `MBHashStr` into a `Multihash` from which the codec, digest size, and digest can be extracted.
    pub fn decoded<const SIZE: usize>(&self) -> Result<Multihash<SIZE>, Error> {
        let (_base, byte_v) = multibase::decode(&self.0)?;
        Ok(Multihash::from_bytes(byte_v.as_slice())?)
    }
}

impl pneutype::Validate for MBHashStr {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        // TODO: Ideally we could do this without allocating (e.g. passing in a stack-allocated array),
        // but that requires support from multibase crate (see https://github.com/multiformats/rust-multibase/pull/70)
        let (_base, byte_v) = multibase::decode(data)?;
        // Use 64 here to accomodate the largest expected digest size (SHA2-512 is 64 bytes).
        let multihash = multihash::Multihash::<64>::from_bytes(byte_v.as_slice())?;
        let codec_category = CodecCategory::from_codec(multihash.code());
        ensure!(
            codec_category == CodecCategory::Multihash,
            "expected codec (0x{:02x}) to be in category {:?} but it was in category {:?}",
            multihash.code(),
            CodecCategory::Multihash,
            codec_category,
        );
        debug_assert_eq!(
            multihash.size() as usize,
            multihash.digest().len(),
            "this should probably be guaranteed by the multihash crate, but just checking anyway"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mb_hash_str_decode() {
        // TODO: Get some test vectors
        let test_case_v = [
            // From <https://www.w3.org/TR/vc-data-integrity/#resource-integrity>
            (
                ssi_multicodec::SHA2_256,
                "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n",
            ),
        ];

        for (codec, multibase_str) in test_case_v {
            let mb_hash = MBHashStr::new_ref(multibase_str).expect("pass");
            let multihash = mb_hash.decoded::<64>().expect("pass");
            assert_eq!(
                multihash.code(),
                codec,
                "multibase_str: {:?}",
                multibase_str
            );
        }
    }
}
