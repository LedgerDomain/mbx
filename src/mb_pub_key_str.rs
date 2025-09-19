use crate::MBPubKeyStr;

impl MBPubKeyStr {
    #[cfg(feature = "signature-dyn")]
    pub fn try_into_key_type(&self) -> crate::Result<signature_dyn::KeyType> {
        Ok(signature_dyn::KeyType::try_from_pub_key_codec(
            self.decoded().expect("programmer error").codec(),
        )?)
    }
    #[cfg(feature = "signature-dyn")]
    pub fn to_verifier_bytes(&self) -> crate::Result<signature_dyn::VerifierBytes> {
        signature_dyn::VerifierBytes::try_from(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mb_pub_key_str_decode() {
        // TODO: This is actually testing MBPubKeyStr, not MBPubKeyStr.
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
        ];

        for (codec, multibase_str) in test_case_v {
            let mb_pub_key = MBPubKeyStr::new_ref(multibase_str).expect("pass");
            let decoded_multi_encoded = mb_pub_key.decoded().expect("pass");
            assert_eq!(
                decoded_multi_encoded.codec(),
                codec,
                "multibase_str: {:?}",
                multibase_str
            );
        }
    }
}
