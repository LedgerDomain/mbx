use crate::{CodecCategorizableT, Error, MBXStr};

/// This newtype is a String defined to be `multibase(base, varint(codec) || bytes)`, where the codec
/// is restricted to a specific CodecCategory.  The `X` in `MBX` signifies a placeholder.
/// This generic type is used in type aliases for `MBPubKey` and `MBPrivKey`, and isn't really
/// intended to be used directly.  See also `MBXStr`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_mbx_str", borrow = "MBXStr", string_field = "1")]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "String", try_from = "String"))]
pub struct MBX<C: CodecCategorizableT>(std::marker::PhantomData<C>, String);

impl<C: CodecCategorizableT> MBX<C> {
    // Note that this doesn't actually check the bytes against the codec (at the very least it should check the
    // length of the bytes against the codec).  TODO: Do this check.
    pub fn encoded(base: multibase::Base, codec: u64, byte_v: &[u8]) -> Result<Self, Error> {
        let multi_encoded = ssi_multicodec::MultiEncodedBuf::encode_bytes(codec, byte_v);
        Ok(Self(
            std::marker::PhantomData,
            multibase::encode(base, multi_encoded.as_bytes()),
        ))
    }
}

impl<C: CodecCategorizableT> From<MBX<C>> for String {
    fn from(mbx: MBX<C>) -> Self {
        mbx.1
    }
}
