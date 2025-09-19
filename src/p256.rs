use crate::{Error, MBPrivKey, MBPrivKeyStr, MBPubKey, MBPubKeyStr, ensure};

//
// SigningKey
//

impl TryFrom<&MBPrivKeyStr> for p256::ecdsa::SigningKey {
    type Error = Error;
    fn try_from(mb_priv_key: &MBPrivKeyStr) -> Result<Self, Self::Error> {
        let decoded = mb_priv_key.decoded()?;
        ensure!(
            decoded.codec() == ssi_multicodec::P256_PRIV,
            "Expected codec P256_PRIV 0x({:02x}), got 0x{:02x}",
            ssi_multicodec::P256_PRIV,
            decoded.codec()
        );
        let bytes = decoded.data();
        let signing_key = p256::ecdsa::SigningKey::from_slice(bytes)?;
        Ok(signing_key)
    }
}

impl TryFrom<&MBPrivKey> for p256::ecdsa::SigningKey {
    type Error = Error;
    fn try_from(mb_priv_key: &MBPrivKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_priv_key.as_mb_priv_key_str())
    }
}

impl TryFrom<MBPrivKey> for p256::ecdsa::SigningKey {
    type Error = Error;
    fn try_from(mb_priv_key: MBPrivKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_priv_key.as_mb_priv_key_str())
    }
}

//
// VerifyingKey
//

impl TryFrom<&MBPubKeyStr> for p256::ecdsa::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: &MBPubKeyStr) -> Result<Self, Self::Error> {
        let decoded = mb_pub_key.decoded()?;
        ensure!(
            decoded.codec() == ssi_multicodec::P256_PUB,
            "Expected codec P256_PUB (0x{:02x}), got 0x{:02x}",
            ssi_multicodec::P256_PUB,
            decoded.codec()
        );
        let compressed_bytes = decoded.data();
        debug_assert_eq!(compressed_bytes.len(), 33);
        let verifying_key = p256::ecdsa::VerifyingKey::try_from(compressed_bytes)?;
        Ok(verifying_key)
    }
}

impl TryFrom<&MBPubKey> for p256::ecdsa::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: &MBPubKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

impl TryFrom<MBPubKey> for p256::ecdsa::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: MBPubKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Base, MBPrivKey, MBPubKey};

    fn test_p256_encode_decode_case(base: Base) {
        let mut rng = rand::rngs::OsRng;
        for _ in 0..10 {
            let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
            let verifying_key = signing_key.verifying_key();

            let mb_pub_key = MBPubKey::from_p256_verifying_key(base, &verifying_key);
            let mb_priv_key = MBPrivKey::from_p256_signing_key(base, &signing_key);

            println!("p256 mb_pub_key: {}", mb_pub_key);
            println!("p256 mb_priv_key: {}", mb_priv_key);

            let verifying_key_decoded =
                p256::ecdsa::VerifyingKey::try_from(&mb_pub_key).expect("pass");
            let signing_key_decoded =
                p256::ecdsa::SigningKey::try_from(&mb_priv_key).expect("pass");

            assert_eq!(verifying_key_decoded, *verifying_key);
            assert_eq!(signing_key_decoded, signing_key);
        }
    }

    #[test]
    fn test_p256_encode_decode() {
        for base in [Base::Base32Lower, Base::Base58Btc, Base::Base64Url] {
            test_p256_encode_decode_case(base);
        }
    }
}
