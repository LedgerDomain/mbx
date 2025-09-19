use crate::{CodecCategorizableT, CodecCategory, Error, ensure};

/// This newtype is a str that is defined to be `multibase(base, varint(codec) || bytes)`, where the
/// codec is restricted to a specific CodecCategory.  The `X` in `MBXStr` signifies a placeholder.
/// This generic type is used in type aliases for `MBPubKeyStr` and `MBPrivKeyStr`, and isn't really
/// intended to be used directly.  See also `MBX`.
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuStr)]
#[pneu_str(str_field = "1")]
#[cfg_attr(feature = "serde", pneu_str(serialize))]
#[repr(transparent)]
pub struct MBXStr<C: CodecCategorizableT>(std::marker::PhantomData<C>, str);

impl<C: CodecCategorizableT> MBXStr<C> {
    /// Returns the base of this MBXStr.
    pub fn base(&self) -> multibase::Base {
        multibase::Base::from_code(self.base_char()).expect("programmer error")
    }
    /// Returns the base character of this MBXStr.
    pub fn base_char(&self) -> char {
        self.1.chars().next().expect("programmer error")
    }
    /// Decodes the `MBXStr<C>` into a `MultiEncodedBuf` from which the codec and bytes can be extracted.
    pub fn decoded(&self) -> Result<ssi_multicodec::MultiEncodedBuf, Error> {
        let (_base, multicodec_byte_v) = multibase::decode(&self.1)?;
        Ok(ssi_multicodec::MultiEncodedBuf::new(multicodec_byte_v)?)
    }
}

#[cfg(feature = "serde")]
impl<'de, C: CodecCategorizableT> serde::Deserialize<'de> for &'de MBXStr<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V<C: CodecCategorizableT>(std::marker::PhantomData<C>);
        impl<'de, C: CodecCategorizableT + 'de> serde::de::Visitor<'de> for V<C> {
            type Value = &'de MBXStr<C>;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a borrowed MBXStr")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                MBXStr::<C>::new_ref(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V::<C>(std::marker::PhantomData))
    }
}

impl<C: CodecCategorizableT> pneutype::Validate for MBXStr<C> {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        // TODO: Ideally we could simply validate the multibase string without allocating.
        let (_decoded_base, decoded_byte_v) = multibase::decode(data)?;
        let multi_encoded = ssi_multicodec::MultiEncodedBuf::new(decoded_byte_v)?;
        let codec_category = CodecCategory::from_codec(multi_encoded.codec());
        #[cfg(feature = "codec-str")]
        ensure!(
            codec_category == C::codec_category(),
            "expected codec {:?} (0x{:02x}) to be in category {:?} but it was in category {:?}",
            crate::codec_str(multi_encoded.codec()),
            multi_encoded.codec(),
            C::codec_category(),
            codec_category,
        );
        #[cfg(not(feature = "codec-str"))]
        ensure!(
            codec_category == C::codec_category(),
            "expected codec 0x{:02x} to be in category {:?} but it was in category {:?}",
            multi_encoded.codec(),
            C::codec_category(),
            codec_category,
        );

        // Codec-specific validation.  For now, just validate the expected byte length.

        // Validate the expected byte length.
        // References:
        // - <https://w3c-ccg.github.io/did-key-spec/#signature-method-creation-algorithm>
        let expected_byte_len_o = match multi_encoded.codec() {
            // Private key types
            ssi_multicodec::ED25519_PRIV => Some(32),
            // ssi_multicodec::ED448_PRIV => Some(57),
            ssi_multicodec::P256_PRIV => Some(32),
            ssi_multicodec::P384_PRIV => Some(48),
            // ssi_multicodec::P521_PRIV => Some(64),
            ssi_multicodec::SECP256K1_PRIV => Some(32),
            // Public key types
            ssi_multicodec::ED25519_PUB => Some(32),
            ssi_multicodec::ED448_PUB => Some(57),
            // Compressed format.
            ssi_multicodec::P256_PUB => Some(33),
            // Compressed format.
            ssi_multicodec::P384_PUB => Some(49),
            // Compressed format.
            ssi_multicodec::P521_PUB => Some(67),
            // Compressed format.
            ssi_multicodec::SECP256K1_PUB => Some(33),
            ssi_multicodec::X25519_PUB => Some(32),
            // No checking for other types for now.
            _ => None,
        };
        if let Some(expected_byte_len) = expected_byte_len_o {
            #[cfg(feature = "codec-str")]
            ensure!(
                multi_encoded.data().len() == expected_byte_len,
                "codec {:?} (0x{:02x}) expected {} bytes but got {}",
                crate::codec_str(multi_encoded.codec()),
                multi_encoded.codec(),
                expected_byte_len,
                multi_encoded.data().len()
            );
            #[cfg(not(feature = "codec-str"))]
            ensure!(
                multi_encoded.data().len() == expected_byte_len,
                "codec 0x{:02x} expected {} bytes but got {}",
                multi_encoded.codec(),
                expected_byte_len,
                multi_encoded.data().len()
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::PubKeyCategory;

    use super::*;

    #[test]
    fn test_mbx_str_decode() {
        let test_case_v = [
            // These are from https://github.com/w3c-ccg/did-key-spec/tree/main/test-vectors

            // bls12-381
            (
                ssi_multicodec::BLS12_381_G2_PUB,
                "zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY",
            ),
            (
                ssi_multicodec::BLS12_381_G2_PUB,
                "zUC77uxiMKceQoxciSy1xgk3nvP8c8NZXDnaY1xsXZaU5UmsZdnwStUke8Ca8zAdPX3MQTHEMhDTCgfdGU7UrY4RRdVhqZp8FaAaoaXFEVp2ZAM7oj3P45BuTCfc3t9FEGBAEQY",
            ),
            (
                ssi_multicodec::BLS12_381_G2_PUB,
                "zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW",
            ),
            (
                ssi_multicodec::BLS12_381_G2_PUB,
                "zUC7FB43ErjeTPiBLZ8wWT3aBTL7QnJ6AAZh9opgV5dKkw291mC23yTnKQ2pTcSgLbdKnVJ1ARn6XrwxWqvFg5dRFzCjwSg1j35nRgs5c2nbqkJ4auPTyPtkJ3xcABRNWaDX6QU",
            ),
            (
                ssi_multicodec::BLS12_381_G2_PUB,
                "zUC7FNFB7UinoJ5tqkeEELWLsytHBdHpwQ7wLVFAYRT6vqdr5uC3JPK6BVNNByj4KxvVKXoirT7VuqptSznjRCgvr7Ksuk42zyFw1GJSYNQSKCpjVcrZXoPUbR1P6zHmr97mVdA",
            ),
            (
                ssi_multicodec::BLS12_381_G1G2_PUB,
                "z5TcCmGLu7HrkT5FTnejDTKcH11LPMQLXMPHTRyzY4KdRvqpPLprH7s1ddWFD38cAkZoiDtofUmJVZyEweUTfwjG5H3znk3ir4tzmuDBUSNbNQ7U6jJqj5bkQLKRaQB1bpFJKGLEq3EBwsfPutL5D7p78kFeLNHznqbf5oGpik7ScaDbGLaTLh1Jtadi6VmPNNd44Cojk",
            ),
            // ed25519
            (
                ssi_multicodec::ED25519_PUB,
                "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
            ),
            (
                ssi_multicodec::ED25519_PUB,
                "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
            ),
            (
                ssi_multicodec::ED25519_PUB,
                "z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
            ),
            (
                ssi_multicodec::ED25519_PUB,
                "z6MkvqoYXQfDDJRv8L4wKzxYeuKyVZBfi9Qo6Ro8MiLH3kDQ",
            ),
            (
                ssi_multicodec::ED25519_PUB,
                "z6MkwYMhwTvsq376YBAcJHy3vyRWzBgn5vKfVqqDCgm7XVKU",
            ),
            // secp256k1
            (
                ssi_multicodec::SECP256K1_PUB,
                "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            ),
            (
                ssi_multicodec::SECP256K1_PUB,
                "zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2",
            ),
            (
                ssi_multicodec::SECP256K1_PUB,
                "zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N",
            ),
            (
                ssi_multicodec::SECP256K1_PUB,
                "zQ3shadCps5JLAHcZiuX5YUtWHHL8ysBJqFLWvjZDKAWUBGzy",
            ),
            (
                ssi_multicodec::SECP256K1_PUB,
                "zQ3shptjE6JwdkeKN4fcpnYQY3m9Cet3NiHdAfpvSUZBFoKBj",
            ),
            (
                ssi_multicodec::SECP256K1_PUB,
                "zQ3shjmnWpSDEbYKpaFm4kTs9kXyqG6N2QwCYHNPP4yubqgJS",
            ),
            // TODO: some that use base64

            // TODO: Some hash values, signature values, etc.
        ];

        for (codec, multibase_str) in test_case_v {
            let mbx = MBXStr::<PubKeyCategory>::new_ref(multibase_str).expect("pass");
            let decoded_multi_encoded = mbx.decoded().expect("pass");
            assert_eq!(
                decoded_multi_encoded.codec(),
                codec,
                "multibase_str: {:?}",
                multibase_str
            );
            // assert_eq!(decoded_multi_encoded.data(), byte_v);
        }
    }
}
