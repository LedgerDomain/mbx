use crate::CodecCategory;

/// A trait that is used to define the sigil for a codec category within generics.
/// Provides a method to get the codec category as an enum.
pub trait CodecCategorizableT: Clone {
    fn codec_category() -> CodecCategory;
}

/// The codec category sigil for hashes (specifically, multihashes).
/// See <https://github.com/multiformats/multicodec/blob/master/table.csv> for specific codecs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MultihashCategory;

/// The codec category sigil for private keys.
/// See <https://github.com/multiformats/multicodec/blob/master/table.csv> for specific codecs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrivKeyCategory;

/// The codec category sigil for public keys.
/// See <https://github.com/multiformats/multicodec/blob/master/table.csv> for specific codecs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PubKeyCategory;

/// The codec category sigil for signatures.
/// See <https://github.com/multiformats/multicodec/blob/master/table.csv> for specific codecs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SignatureCategory;

/// The codec category sigil for symmetric keys.
/// See <https://github.com/multiformats/multicodec/blob/master/table.csv> for specific codecs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SymmetricKeyCategory;

// #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
// pub struct Unspecified;

impl CodecCategorizableT for MultihashCategory {
    fn codec_category() -> CodecCategory {
        CodecCategory::Multihash
    }
}

impl CodecCategorizableT for PrivKeyCategory {
    fn codec_category() -> CodecCategory {
        CodecCategory::PrivKey
    }
}

impl CodecCategorizableT for PubKeyCategory {
    fn codec_category() -> CodecCategory {
        CodecCategory::PubKey
    }
}

impl CodecCategorizableT for SignatureCategory {
    fn codec_category() -> CodecCategory {
        CodecCategory::Signature
    }
}

impl CodecCategorizableT for SymmetricKeyCategory {
    fn codec_category() -> CodecCategory {
        CodecCategory::SymmetricKey
    }
}
