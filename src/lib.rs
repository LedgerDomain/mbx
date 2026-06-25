#[cfg(feature = "blake3")]
mod blake3;
mod codec_categorizable_t;
mod codec_category;
#[cfg(feature = "codec-str")]
mod codec_str;
#[cfg(feature = "ed25519-dalek")]
mod ed25519_dalek;
#[cfg(feature = "ed448-goldilocks")]
mod ed448_goldilocks;
mod error;
#[cfg(feature = "k256")]
mod k256;
mod mb_hash;
mod mb_hash_str;
mod mb_priv_key;
mod mb_priv_key_str;
mod mb_pub_key;
mod mb_pub_key_str;
mod mbx;
mod mbx_str;
#[cfg(feature = "p256")]
mod p256;
#[cfg(feature = "p384")]
mod p384;
#[cfg(feature = "p521")]
mod p521;
#[cfg(feature = "sha2")]
mod sha2;
#[cfg(feature = "sha3")]
mod sha3;
#[cfg(feature = "signature-dyn")]
mod signature_dyn;

#[cfg(feature = "codec-str")]
pub use codec_str::codec_str;
pub(crate) use mbx_str::mbx_str_validate_impl;
pub use {
    codec_categorizable_t::{CodecCategorizableT, PrivKeyCategory, PubKeyCategory},
    codec_category::CodecCategory,
    error::Error,
    mb_hash::MBHash,
    mb_hash_str::MBHashStr,
    mb_priv_key::MBPrivKey,
    mb_priv_key_str::MBPrivKeyStr,
    mb_pub_key::MBPubKey,
    mb_pub_key_str::MBPubKeyStr,
    mbx::MBX,
    mbx_str::MBXStr,
};
pub type Result<T> = std::result::Result<T, Error>;

/// Defines the various available base-encodings.  The recommended base-encoding is Base::Base64Url.
/// Base::Base58Btc is used in the did:key DID method.
pub type Base = multibase::Base;
/// Represents a multihash value (see <https://github.com/multiformats/multihash#format>).
pub type Multihash<const SIZE: usize> = multihash::Multihash<SIZE>;
/// Represents a multiencoded byte sequence, for example the bytes that are encoded to form
/// a publicKeyMultibase value (see <https://www.w3.org/TR/cid-1.0/#Multikey>).
pub type MultiEncodedBuf = ssi_multicodec::MultiEncodedBuf;

/// TEMPORARY until ssi_multicodec supports the ED448_PRIV codec.
/// See https://github.com/multiformats/multicodec/pull/390
pub(crate) const ED448_PRIV_CODEC: u64 = 0x1311;
