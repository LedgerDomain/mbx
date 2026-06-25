use crate::{
    ED448_PRIV_CODEC, Error, MBPubKey, PrivKeyCategory, Result, bail, mbx_str_validate_impl,
};

/// This newtype is a str representing a publicKeyMultibase value (see <https://www.w3.org/TR/cid-1.0/#Multikey>).
/// See also `MBPrivKey`.
#[derive(Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuStr)]
#[pneu_str(omit_display)]
#[cfg_attr(feature = "serde", pneu_str(deserialize, serialize))]
#[repr(transparent)]
pub struct MBPrivKeyStr(str);

impl MBPrivKeyStr {
    /// Returns the base of this MBPrivKeyStr.
    pub fn base(&self) -> multibase::Base {
        multibase::Base::from_code(self.base_char()).expect("programmer error")
    }
    /// Returns the base character of this MBPrivKeyStr.
    pub fn base_char(&self) -> char {
        self.0.chars().next().expect("programmer error")
    }
    /// Decodes the `MBPrivKeyStr` into a `MultiEncodedBuf` from which the codec and bytes can be extracted.
    pub fn decoded(&self) -> Result<ssi_multicodec::MultiEncodedBuf> {
        let (_base, multicodec_byte_v) = multibase::decode(&self.0)?;
        Ok(ssi_multicodec::MultiEncodedBuf::new(multicodec_byte_v)?)
    }
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
            ED448_PRIV_CODEC => {
                // NOTE: The codec ED448_PRIV exists but is not yet supported by the ssi_multicodec crate,
                // hence the hardcoded value.  See https://github.com/multiformats/multicodec/pull/390
                // TODO: Eventually replace ED448_PRIV_CODEC with `ssi_multicodec::ED448_PRIV => { ... }`
                #[cfg(feature = "ed448-goldilocks")]
                {
                    let signing_key = ed448_goldilocks::SigningKey::try_from(self)?;
                    Ok(MBPubKey::from_ed448_goldilocks_verifying_key(
                        self.base(),
                        &signing_key.verifying_key(),
                    ))
                }
                #[cfg(not(feature = "ed448-goldilocks"))]
                {
                    bail!(
                        "MBPrivKeyStr::mb_pub_key is only implemented for ed448 key type if the \"ed448-goldilocks\" feature is enabled"
                    );
                }
            }
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

impl std::fmt::Debug for MBPrivKeyStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MBPrivKeyStr(<REDACTED>)")
    }
}

impl pneutype::Validate for MBPrivKeyStr {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> std::result::Result<(), Self::Error> {
        use crate::CodecCategorizableT;
        mbx_str_validate_impl(data, PrivKeyCategory::codec_category())
    }
}
