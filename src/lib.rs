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
#[cfg(feature = "signature-dyn")]
mod signature_dyn;

#[cfg(feature = "codec-str")]
pub use codec_str::codec_str;
pub use {
    codec_categorizable_t::{CodecCategorizableT, PrivKeyCategory, PubKeyCategory},
    codec_category::CodecCategory,
    error::Error,
    mb_hash::MBHash,
    mb_hash_str::MBHashStr,
    mbx::MBX,
    mbx_str::MBXStr,
};
/// This newtype is a String representing a secretKeyMultibase value (see <https://www.w3.org/TR/cid-1.0/#Multikey>).
/// See also `MBPrivKeyStr`.
pub type MBPrivKey = MBX<PrivKeyCategory>;
/// This newtype is a str representing a publicKeyMultibase value (see <https://www.w3.org/TR/cid-1.0/#Multikey>).
/// See also `MBPrivKey`.
pub type MBPrivKeyStr = MBXStr<PrivKeyCategory>;
/// This newtype is a String representing a publicKeyMultibase value (see <https://www.w3.org/TR/cid-1.0/#Multikey>).
/// See also `MBPubKeyStr`.
pub type MBPubKey = MBX<PubKeyCategory>;
/// This newtype is a str representing a publicKeyMultibase value (see <https://www.w3.org/TR/cid-1.0/#Multikey>).
/// See also `MBPubKey`.
pub type MBPubKeyStr = MBXStr<PubKeyCategory>;
pub type Result<T> = std::result::Result<T, Error>;

/// Defines the various available base-encodings.  The recommended base-encoding is Base::Base64Url.
/// Base::Base58Btc is used in the did:key DID method.
pub type Base = multibase::Base;
/// Represents a multihash value (see <https://github.com/multiformats/multihash#format>).
pub type Multihash<const SIZE: usize> = multihash::Multihash<SIZE>;
/// Represents a multiencoded byte sequence, for example the bytes that are encoded to form
/// a publicKeyMultibase value (see <https://www.w3.org/TR/cid-1.0/#Multikey>).
pub type MultiEncodedBuf = ssi_multicodec::MultiEncodedBuf;

impl MBPrivKey {
    pub fn as_mb_priv_key_str(&self) -> &MBPrivKeyStr {
        self.as_mbx_str()
    }
}

impl MBPubKey {
    pub fn as_mb_pub_key_str(&self) -> &MBPubKeyStr {
        self.as_mbx_str()
    }
}
