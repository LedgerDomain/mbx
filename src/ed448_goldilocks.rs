use crate::{Error, MBPubKey, MBPubKeyStr, ensure, error};

//
// SigningKey
//

// NOTE: The codec ED448_PRIV does not yet exist.  See https://github.com/multiformats/multicodec/pull/390
// impl TryFrom<&MBPrivKeyStr> for ed448_goldilocks::SigningKey {
//     type Error = Error;
//     fn try_from(mb_priv_key: &MBPrivKeyStr) -> Result<Self, Self::Error> {
//         let decoded = mb_priv_key.decoded()?;
//         ensure!(
//             decoded.codec() == ssi_multicodec::ED448_PRIV,
//             "Expected codec ED448_PRIV 0x({:02x}), got 0x{:02x}",
//             ssi_multicodec::ED448_PRIV,
//             decoded.codec()
//         );
//         let bytes = decoded.data();
//         let signing_key = ed448_goldilocks::SigningKey::try_from(bytes)?;
//         Ok(signing_key)
//     }
// }

// impl TryFrom<&MBPrivKey> for ed448_goldilocks::SigningKey {
//     type Error = Error;
//     fn try_from(mb_priv_key: &MBPrivKey) -> Result<Self, Self::Error> {
//         Self::try_from(mb_priv_key.as_mb_priv_key_str())
//     }
// }

// impl TryFrom<MBPrivKey> for ed448_goldilocks::SigningKey {
//     type Error = Error;
//     fn try_from(mb_priv_key: MBPrivKey) -> Result<Self, Self::Error> {
//         Self::try_from(mb_priv_key.as_mb_priv_key_str())
//     }
// }

//
// VerifyingKey
//

impl TryFrom<&MBPubKeyStr> for ed448_goldilocks::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: &MBPubKeyStr) -> Result<Self, Self::Error> {
        let decoded = mb_pub_key.decoded()?;
        ensure!(
            decoded.codec() == ssi_multicodec::ED448_PUB,
            "Expected codec ED448_PUB 0x({:02x}), got 0x{:02x}",
            ssi_multicodec::ED448_PUB,
            decoded.codec()
        );
        let bytes = decoded.data();
        let byte_array = <&[u8; 57]>::try_from(bytes).map_err(|_| {
            error!(
                "Invalid ED448 public key; incorrect length -- got {} bytes, expected 57",
                bytes.len(),
            )
        })?;
        let verifying_key = ed448_goldilocks::VerifyingKey::from_bytes(byte_array)?;
        Ok(verifying_key)
    }
}

impl TryFrom<&MBPubKey> for ed448_goldilocks::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: &MBPubKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

impl TryFrom<MBPubKey> for ed448_goldilocks::VerifyingKey {
    type Error = Error;
    fn try_from(mb_pub_key: MBPubKey) -> Result<Self, Self::Error> {
        Self::try_from(mb_pub_key.as_mb_pub_key_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Base, MBPubKey};

    fn test_ed448_goldilocks_encode_decode_mb_pub_key_case(base: Base) {
        let signing_key = ed448_goldilocks::SigningKey::generate(
            &mut rand_0_9::rand_core::UnwrapMut(&mut rand_0_9::rngs::OsRng),
        );
        let verifying_key = signing_key.verifying_key();

        let mb_pub_key = MBPubKey::from_ed448_goldilocks_verifying_key(base, &verifying_key);

        println!("ed448_goldilocks mb_pub_key: {}", mb_pub_key);

        let verifying_key_decoded =
            ed448_goldilocks::VerifyingKey::try_from(&mb_pub_key).expect("pass");

        assert_eq!(verifying_key_decoded, verifying_key);
    }

    #[test]
    fn test_ed448_goldilocks_encode_decode() {
        for base in [
            Base::Base16Lower,
            Base::Base32Lower,
            Base::Base58Btc,
            Base::Base64Url,
        ] {
            test_ed448_goldilocks_encode_decode_mb_pub_key_case(base);
        }
    }

    // use crate::{Base, MBPrivKey, MBPubKey};

    // fn test_ed448_goldilocks_encode_decode_case(base: Base) {
    //     let mut rng = rand::rngs::OsRng;
    //     let signing_key = ed448_goldilocks::SigningKey::generate(&mut rng);
    //     let verifying_key = signing_key.verifying_key();

    //     let mb_pub_key = MBPubKey::from_ed448_goldilocks_verifying_key(base, &verifying_key);
    //     let mb_priv_key = MBPrivKey::from_ed448_goldilocks_signing_key(base, &signing_key);

    //     println!("ed448_goldilocks mb_pub_key: {}", mb_pub_key);
    //     println!("ed448_goldilocks mb_priv_key: {}", mb_priv_key);

    //     let signing_key_decoded =
    //         ed448_goldilocks::SigningKey::try_from(&mb_priv_key).expect("pass");
    //     let verifying_key_decoded =
    //         ed448_goldilocks::VerifyingKey::try_from(&mb_pub_key).expect("pass");

    //     assert_eq!(signing_key_decoded, signing_key);
    //     assert_eq!(verifying_key_decoded, verifying_key);
    // }

    // #[test]
    // fn test_ed448_goldilocks_encode_decode() {
    //     for base in [
    //         Base::Base16Lower,
    //         Base::Base32Lower,
    //         Base::Base58Btc,
    //         Base::Base64Url,
    //     ] {
    //         test_ed448_goldilocks_encode_decode_case(base);
    //     }
    // }
}
