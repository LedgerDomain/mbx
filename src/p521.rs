use crate::{Error, MBPrivKey, MBPrivKeyStr, MBPubKey, MBPubKeyStr, ensure};

//
// SigningKey
//

impl TryFrom<&MBPrivKeyStr> for p521::ecdsa::SigningKey {
    type Error = Error;
    fn try_from(mb_priv_key: &MBPrivKeyStr) -> Result<Self, Self::Error> {
        let decoded = mb_priv_key.decoded()?;
        ensure!(
            decoded.codec() == ssi_multicodec::P521_PRIV,
            "Expected codec P521_PRIV 0x({:02x}), got 0x{:02x}",
            ssi_multicodec::P521_PRIV,
            decoded.codec()
        );
        let bytes = decoded.data();
        let signing_key = p521::ecdsa::SigningKey::from_slice(bytes)?;
        Ok(signing_key)
    }
}

impl TryFrom<&MBPrivKey> for p521::ecdsa::SigningKey {
    type Error = Error;
    fn try_from(mb_priv_key: &MBPrivKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_priv_key.as_mb_priv_key_str())
    }
}

impl TryFrom<MBPrivKey> for p521::ecdsa::SigningKey {
    type Error = Error;
    fn try_from(mb_priv_key: MBPrivKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_priv_key.as_mb_priv_key_str())
    }
}

//
// VerifyingKey
//

impl TryFrom<&MBPubKeyStr> for p521::ecdsa::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: &MBPubKeyStr) -> Result<Self, Self::Error> {
        let decoded = mb_pub_key.decoded()?;
        ensure!(
            decoded.codec() == ssi_multicodec::P521_PUB,
            "Expected codec P521_PUB (0x{:02x}), got 0x{:02x}",
            ssi_multicodec::P521_PUB,
            decoded.codec()
        );
        let compressed_bytes = decoded.data();
        debug_assert_eq!(compressed_bytes.len(), 67);
        let verifying_key = p521::ecdsa::VerifyingKey::try_from(compressed_bytes)?;
        Ok(verifying_key)
    }
}

impl TryFrom<&MBPubKey> for p521::ecdsa::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: &MBPubKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

impl TryFrom<MBPubKey> for p521::ecdsa::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: MBPubKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Base, MBPrivKey, MBPubKey};

    fn test_p521_encode_decode_case(base: Base) {
        for _ in 0..10 {
            let signing_key = p521::ecdsa::SigningKey::random(&mut rand_0_9::rand_core::UnwrapMut(
                &mut rand_0_9::rngs::OsRng,
            ));
            let verifying_key = signing_key.verifying_key();

            let mb_pub_key = MBPubKey::from_p521_verifying_key(base, &verifying_key);
            let mb_priv_key = MBPrivKey::from_p521_signing_key(base, &signing_key);

            println!("p521 mb_pub_key: {}", mb_pub_key);
            println!("p521 mb_priv_key: {}", mb_priv_key);

            let verifying_key_decoded =
                p521::ecdsa::VerifyingKey::try_from(&mb_pub_key).expect("pass");
            let signing_key_decoded =
                p521::ecdsa::SigningKey::try_from(&mb_priv_key).expect("pass");

            assert_eq!(verifying_key_decoded, *verifying_key);
            assert_eq!(signing_key_decoded, signing_key);
        }
    }

    #[test]
    fn test_p521_encode_decode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_p521_encode_decode_case(base);
        }
    }
}
