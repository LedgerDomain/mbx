use crate::{Error, MBPrivKeyStr};

/// This newtype is a String representing a secretKeyMultibase value (see <https://www.w3.org/TR/cid-1.0/#Multikey>).
/// See also `MBPrivKeyStr`.  Note that this does not impl `std::fmt::Debug`, `std::fmt::Display` or `fn into_string`,
/// so that its content can be properly redacted and zeroized without leaking.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuString, zeroize::Zeroize)]
#[pneu_string(
    as_pneu_str = "as_mb_priv_key_str",
    borrow = "MBPrivKeyStr",
    omit_display,
    omit_into_string
)]
#[cfg_attr(feature = "serde", pneu_string(deserialize, serialize))]
pub struct MBPrivKey(String);

impl MBPrivKey {
    // Note that this doesn't actually check the bytes against the codec (at the very least it should check the
    // length of the bytes against the codec).  TODO: Do this check.
    pub fn encoded(base: multibase::Base, codec: u64, byte_v: &[u8]) -> Result<Self, Error> {
        let multi_encoded = ssi_multicodec::MultiEncodedBuf::encode_bytes(codec, byte_v);
        Ok(Self(multibase::encode(base, multi_encoded.as_bytes())))
    }
    #[cfg(feature = "ed25519-dalek")]
    pub fn from_ed25519_dalek_signing_key(
        base: multibase::Base,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        Self::encoded(base, ssi_multicodec::ED25519_PRIV, signing_key.as_bytes()).unwrap()
    }
    // NOTE: The codec ED448_PRIV is not yet supported by the ssi_multicodec crate,
    // hence the hardcoded value.  See https://github.com/multiformats/multicodec/pull/390
    // TODO: Eventually replace ED448_PRIV_CODEC with `ssi_multicodec::ED448_PRIV => { ... }`
    #[cfg(feature = "ed448-goldilocks")]
    pub fn from_ed448_goldilocks_signing_key(
        base: multibase::Base,
        signing_key: &ed448_goldilocks::SigningKey,
    ) -> Self {
        use crate::ED448_PRIV_CODEC;

        Self::encoded(base, ED448_PRIV_CODEC, signing_key.as_bytes()).unwrap()
    }
    #[cfg(feature = "k256")]
    pub fn from_k256_signing_key(
        base: multibase::Base,
        signing_key: &k256::ecdsa::SigningKey,
    ) -> Self {
        MBPrivKey::encoded(
            base,
            ssi_multicodec::SECP256K1_PRIV,
            &signing_key.to_bytes(),
        )
        .unwrap()
    }
    #[cfg(feature = "p256")]
    pub fn from_p256_signing_key(
        base: multibase::Base,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> Self {
        MBPrivKey::encoded(base, ssi_multicodec::P256_PRIV, &signing_key.to_bytes()).unwrap()
    }
    #[cfg(feature = "p384")]
    pub fn from_p384_signing_key(
        base: multibase::Base,
        signing_key: &p384::ecdsa::SigningKey,
    ) -> Self {
        MBPrivKey::encoded(base, ssi_multicodec::P384_PRIV, &signing_key.to_bytes()).unwrap()
    }
    #[cfg(feature = "p521")]
    pub fn from_p521_signing_key(
        base: multibase::Base,
        signing_key: &p521::ecdsa::SigningKey,
    ) -> Self {
        MBPrivKey::encoded(base, ssi_multicodec::P521_PRIV, &signing_key.to_bytes()).unwrap()
    }
    #[cfg(feature = "signature-dyn")]
    pub fn try_from_signer_bytes(
        base: crate::Base,
        signer_bytes: signature_dyn::SignerBytes,
    ) -> crate::Result<Self> {
        let codec = signer_bytes.key_type().as_priv_key_codec();
        Ok(Self::encoded(base, codec, signer_bytes.bytes())?)
    }
}

impl std::fmt::Debug for MBPrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MBPrivKey(<REDACTED>)")
    }
}

impl Drop for MBPrivKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl zeroize::ZeroizeOnDrop for MBPrivKey {}
