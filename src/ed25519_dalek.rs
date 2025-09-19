use crate::{Error, MBPrivKey, MBPrivKeyStr, MBPubKey, MBPubKeyStr, ensure};

//
// SigningKey
//

impl TryFrom<&MBPrivKeyStr> for ed25519_dalek::SigningKey {
    type Error = Error;
    fn try_from(mb_priv_key: &MBPrivKeyStr) -> Result<Self, Self::Error> {
        let decoded = mb_priv_key.decoded()?;
        ensure!(
            decoded.codec() == ssi_multicodec::ED25519_PRIV,
            "Expected codec ED25519_PRIV 0x({:02x}), got 0x{:02x}",
            ssi_multicodec::ED25519_PRIV,
            decoded.codec()
        );
        let bytes = decoded.data();
        let signing_key = ed25519_dalek::SigningKey::try_from(bytes)?;
        Ok(signing_key)
    }
}

impl TryFrom<&MBPrivKey> for ed25519_dalek::SigningKey {
    type Error = Error;
    fn try_from(mb_priv_key: &MBPrivKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_priv_key.as_mb_priv_key_str())
    }
}

impl TryFrom<MBPrivKey> for ed25519_dalek::SigningKey {
    type Error = Error;
    fn try_from(mb_priv_key: MBPrivKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_priv_key.as_mb_priv_key_str())
    }
}

//
// VerifyingKey
//

impl TryFrom<&MBPubKeyStr> for ed25519_dalek::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: &MBPubKeyStr) -> Result<Self, Self::Error> {
        let decoded = mb_pub_key.decoded()?;
        ensure!(
            decoded.codec() == ssi_multicodec::ED25519_PUB,
            "Expected codec ED25519_PUB 0x({:02x}), got 0x{:02x}",
            ssi_multicodec::ED25519_PUB,
            decoded.codec()
        );
        let bytes = decoded.data();
        let verifying_key = ed25519_dalek::VerifyingKey::try_from(bytes)?;
        Ok(verifying_key)
    }
}

impl TryFrom<&MBPubKey> for ed25519_dalek::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: &MBPubKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

impl TryFrom<MBPubKey> for ed25519_dalek::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: MBPubKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Base, MBPrivKey, MBPubKey};

    fn test_ed25519_dalek_encode_decode_case(base: Base) {
        let mut rng = rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let mb_pub_key = MBPubKey::from_ed25519_dalek_verifying_key(base, &verifying_key);
        let mb_priv_key = MBPrivKey::from_ed25519_dalek_signing_key(base, &signing_key);

        println!("ed25519_dalek mb_pub_key: {}", mb_pub_key);
        println!("ed25519_dalek mb_priv_key: {}", mb_priv_key);

        let signing_key_decoded = ed25519_dalek::SigningKey::try_from(&mb_priv_key).expect("pass");
        let verifying_key_decoded =
            ed25519_dalek::VerifyingKey::try_from(&mb_pub_key).expect("pass");

        assert_eq!(signing_key_decoded, signing_key);
        assert_eq!(verifying_key_decoded, verifying_key);
    }

    #[test]
    fn test_ed25519_dalek_encode_decode() {
        for base in [
            Base::Base16Lower,
            Base::Base32Lower,
            Base::Base58Btc,
            Base::Base64Url,
        ] {
            test_ed25519_dalek_encode_decode_case(base);
        }
    }
}
