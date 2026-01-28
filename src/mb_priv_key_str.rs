use crate::{MBPrivKeyStr, MBPubKey, Result, bail};

impl MBPrivKeyStr {
    #[cfg(feature = "signature-dyn")]
    pub fn key_type(&self) -> Result<signature_dyn::KeyType> {
        // TODO: Do this without allocation.
        Ok(signature_dyn::KeyType::try_from_priv_key_codec(
            self.decoded()?.codec(),
        )?)
    }
    #[cfg(feature = "signature-dyn")]
    pub fn to_signer_bytes(&self) -> Result<signature_dyn::SignerBytes<'_>> {
        signature_dyn::SignerBytes::try_from(self)
    }
    pub fn pub_key(&self) -> Result<MBPubKey> {
        let decoded = self.decoded()?;
        match decoded.codec() {
            ssi_multicodec::ED25519_PRIV => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let signing_key = ed25519_dalek::SigningKey::try_from(self)?;
                    Ok(MBPubKey::from_ed25519_dalek_verifying_key(
                        self.base(),
                        &signing_key.verifying_key(),
                    ))
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    bail!(
                        "MBPrivKeyStr::mb_pub_key is only implemented for ed25519 key type if the \"ed25519-dalek\" feature is enabled"
                    );
                }
            }
            // NOTE: The codec ED448_PRIV does not yet exist.  See https://github.com/multiformats/multicodec/pull/390
            // ssi_multicodec::ED448_PRIV => {
            //     #[cfg(feature = "ed448-goldilocks")]
            //     {
            //         let signing_key = ed448_goldilocks::SigningKey::try_from(self)?;
            //         Ok(MBPubKey::from_ed448_goldilocks_verifying_key(
            //             self.base(),
            //             &signing_key.verifying_key(),
            //         ))
            //     }
            //     #[cfg(not(feature = "ed448-goldilocks"))]
            //     {
            //         bail!(
            //             "MBPrivKeyStr::mb_pub_key is only implemented for ed448 key type if the \"ed448-goldilocks\" feature is enabled"
            //         );
            //     }
            // }
            ssi_multicodec::SECP256K1_PRIV => {
                #[cfg(feature = "k256")]
                {
                    let signing_key = k256::ecdsa::SigningKey::try_from(self)?;
                    Ok(MBPubKey::from_k256_verifying_key(
                        self.base(),
                        &signing_key.verifying_key(),
                    ))
                }
                #[cfg(not(feature = "k256"))]
                {
                    bail!(
                        "MBPrivKeyStr::mb_pub_key is only implemented for secp256k1 key type if the \"k256\" feature is enabled"
                    );
                }
            }
            ssi_multicodec::P256_PRIV => {
                #[cfg(feature = "p256")]
                {
                    let signing_key = p256::ecdsa::SigningKey::try_from(self)?;
                    Ok(MBPubKey::from_p256_verifying_key(
                        self.base(),
                        &signing_key.verifying_key(),
                    ))
                }
                #[cfg(not(feature = "p256"))]
                {
                    bail!(
                        "MBPrivKeyStr::mb_pub_key is only implemented for p256 key type if the \"p256\" feature is enabled"
                    );
                }
            }
            ssi_multicodec::P384_PRIV => {
                #[cfg(feature = "p384")]
                {
                    let signing_key = p384::ecdsa::SigningKey::try_from(self)?;
                    Ok(MBPubKey::from_p384_verifying_key(
                        self.base(),
                        &signing_key.verifying_key(),
                    ))
                }
                #[cfg(not(feature = "p384"))]
                {
                    bail!(
                        "MBPrivKeyStr::mb_pub_key is only implemented for p384 key type if the \"p384\" feature is enabled"
                    );
                }
            }
            ssi_multicodec::P521_PRIV => {
                #[cfg(feature = "p521")]
                {
                    let signing_key = p521::ecdsa::SigningKey::try_from(self)?;
                    Ok(MBPubKey::from_p521_verifying_key(
                        self.base(),
                        &signing_key.verifying_key(),
                    ))
                }
                #[cfg(not(feature = "p521"))]
                {
                    bail!(
                        "MBPrivKeyStr::mb_pub_key is only implemented for p521 key type if the \"p521\" feature is enabled"
                    );
                }
            }
            _ => {
                bail!("Unsupported codec: 0x{:02x}", decoded.codec());
            }
        }
    }
}
