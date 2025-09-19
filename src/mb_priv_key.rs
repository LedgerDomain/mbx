use crate::MBPrivKey;

impl MBPrivKey {
    #[cfg(feature = "ed25519-dalek")]
    pub fn from_ed25519_dalek_signing_key(
        base: multibase::Base,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        Self::encoded(base, ssi_multicodec::ED25519_PRIV, signing_key.as_bytes()).unwrap()
    }
    // NOTE: The codec ED448_PRIV does not yet exist.  See https://github.com/multiformats/multicodec/pull/390
    // #[cfg(feature = "ed448-goldilocks")]
    // pub fn from_ed448_goldilocks_signing_key(
    //     base: multibase::Base,
    //     signing_key: &ed448_goldilocks::SigningKey,
    // ) -> Self {
    //     Self::encoded(base, ssi_multicodec::ED448_PRIV, signing_key.as_bytes()).unwrap()
    // }
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
