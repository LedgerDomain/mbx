use crate::{Error, MBPrivKey, MBPrivKeyStr, MBPubKey, MBPubKeyStr};

//
// SignerBytes
//

impl<'a> TryFrom<&MBPrivKey> for signature_dyn::SignerBytes<'a> {
    type Error = Error;
    fn try_from(mb_priv_key: &MBPrivKey) -> std::result::Result<Self, Self::Error> {
        Self::try_from(mb_priv_key.as_mb_priv_key_str())
    }
}

impl<'a> TryFrom<MBPrivKey> for signature_dyn::SignerBytes<'a> {
    type Error = Error;
    fn try_from(mb_priv_key: MBPrivKey) -> std::result::Result<Self, Self::Error> {
        Self::try_from(mb_priv_key.as_mb_priv_key_str())
    }
}

impl<'a> TryFrom<&MBPrivKeyStr> for signature_dyn::SignerBytes<'a> {
    type Error = Error;
    fn try_from(mb_priv_key_str: &MBPrivKeyStr) -> std::result::Result<Self, Self::Error> {
        let decoded = mb_priv_key_str.decoded().expect("programmer error");
        let key_type = signature_dyn::KeyType::try_from_priv_key_codec(decoded.codec())?;
        Ok(signature_dyn::SignerBytes::new(
            key_type,
            decoded.data().to_owned().into(),
        )?)
    }
}

//
// VerifierBytes
//

impl<'a> TryFrom<&MBPubKey> for signature_dyn::VerifierBytes<'a> {
    type Error = Error;
    fn try_from(mb_pub_key: &MBPubKey) -> std::result::Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

impl<'a> TryFrom<MBPubKey> for signature_dyn::VerifierBytes<'a> {
    type Error = Error;
    fn try_from(mb_pub_key: MBPubKey) -> std::result::Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

impl<'a> TryFrom<&MBPubKeyStr> for signature_dyn::VerifierBytes<'a> {
    type Error = Error;
    fn try_from(mb_pub_key_str: &MBPubKeyStr) -> std::result::Result<Self, Self::Error> {
        let decoded = mb_pub_key_str.decoded().expect("programmer error");
        let key_type = signature_dyn::KeyType::try_from_pub_key_codec(decoded.codec())?;
        Ok(signature_dyn::VerifierBytes::new(
            key_type,
            decoded.data().to_owned().into(),
        )?)
    }
}
