use crate::MBPubKey;

impl MBPubKey {
    #[cfg(feature = "ed25519-dalek")]
    pub fn from_ed25519_dalek_verifying_key(
        base: crate::Base,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Self {
        Self::encoded(base, ssi_multicodec::ED25519_PUB, verifying_key.as_ref()).unwrap()
    }
    #[cfg(feature = "ed448-goldilocks")]
    pub fn from_ed448_goldilocks_verifying_key(
        base: crate::Base,
        verifying_key: &ed448_goldilocks::VerifyingKey,
    ) -> Self {
        Self::encoded(base, ssi_multicodec::ED448_PUB, verifying_key.as_ref()).unwrap()
    }
    #[cfg(feature = "k256")]
    pub fn from_k256_verifying_key(
        base: crate::Base,
        verifying_key: &k256::ecdsa::VerifyingKey,
    ) -> Self {
        let encoded_point = verifying_key.to_encoded_point(true);
        let compressed_bytes = encoded_point.as_bytes();
        debug_assert_eq!(compressed_bytes.len(), 33);
        MBPubKey::encoded(base, ssi_multicodec::SECP256K1_PUB, compressed_bytes).unwrap()
    }
    #[cfg(feature = "p256")]
    pub fn from_p256_verifying_key(
        base: crate::Base,
        verifying_key: &p256::ecdsa::VerifyingKey,
    ) -> Self {
        let encoded_point = verifying_key.to_encoded_point(true);
        let compressed_bytes = encoded_point.as_bytes();
        debug_assert_eq!(compressed_bytes.len(), 33);
        MBPubKey::encoded(base, ssi_multicodec::P256_PUB, compressed_bytes).unwrap()
    }
    #[cfg(feature = "p384")]
    pub fn from_p384_verifying_key(
        base: crate::Base,
        verifying_key: &p384::ecdsa::VerifyingKey,
    ) -> Self {
        let encoded_point = verifying_key.to_encoded_point(true);
        let compressed_bytes = encoded_point.as_bytes();
        debug_assert_eq!(compressed_bytes.len(), 49);
        MBPubKey::encoded(base, ssi_multicodec::P384_PUB, compressed_bytes).unwrap()
    }
    #[cfg(feature = "p521")]
    pub fn from_p521_verifying_key(
        base: crate::Base,
        verifying_key: &p521::ecdsa::VerifyingKey,
    ) -> Self {
        let encoded_point = verifying_key.to_encoded_point(true);
        let compressed_bytes = encoded_point.as_bytes();
        debug_assert_eq!(compressed_bytes.len(), 67);
        MBPubKey::encoded(base, ssi_multicodec::P521_PUB, compressed_bytes).unwrap()
    }
    #[cfg(feature = "signature-dyn")]
    pub fn try_from_verifier_bytes(
        base: crate::Base,
        verifier_bytes: &signature_dyn::VerifierBytes,
    ) -> crate::Result<Self> {
        Self::encoded(
            base,
            verifier_bytes.key_type().as_pub_key_codec(),
            verifier_bytes.bytes(),
        )
    }
}
