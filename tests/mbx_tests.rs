use mbx::MBPubKeyStr;

fn test_mb_hash_placeholder_case(base: multibase::Base, codec: u64, digest_byte_v: &[u8]) {
    use mbx::MBHash;

    // NOTE: We use 64 here to accomodate the largest expected digest size (SHA2-512 is 64 bytes).
    let mb_hash = MBHash::encoded::<64>(base, codec, digest_byte_v).expect("pass");
    #[cfg(feature = "codec-str")]
    {
        println!(
            "placeholder case: base: {:?}, codec: {} (0x{:02x}), mb_hash: {:?}",
            base,
            mbx::codec_str(codec).expect("pass"),
            codec,
            mb_hash
        );
    }
    #[cfg(not(feature = "codec-str"))]
    {
        println!(
            "placeholder case: base: {:?}, codec: 0x{:02x}, mb_hash: {:?}",
            base, codec, mb_hash
        );
    }
}

#[test]
fn test_mb_hash_placeholder() {
    for base in [
        multibase::Base::Base32Lower,
        multibase::Base::Base58Btc,
        multibase::Base::Base64Url,
    ] {
        test_mb_hash_placeholder_case(base, ssi_multicodec::BLAKE3, &[0u8; 32]);
        test_mb_hash_placeholder_case(base, ssi_multicodec::SHA2_224, &[0u8; 28]);
        test_mb_hash_placeholder_case(base, ssi_multicodec::SHA2_256, &[0u8; 32]);
        test_mb_hash_placeholder_case(base, ssi_multicodec::SHA2_384, &[0u8; 48]);
        test_mb_hash_placeholder_case(base, ssi_multicodec::SHA2_512, &[0u8; 64]);
        test_mb_hash_placeholder_case(base, ssi_multicodec::SHA3_224, &[0u8; 28]);
        test_mb_hash_placeholder_case(base, ssi_multicodec::SHA3_256, &[0u8; 32]);
        test_mb_hash_placeholder_case(base, ssi_multicodec::SHA3_384, &[0u8; 48]);
        test_mb_hash_placeholder_case(base, ssi_multicodec::SHA3_512, &[0u8; 64]);
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_serde_mb_hash_placeholder() {
    use mbx::{MBHash, MBHashStr};

    let byte_v = vec![0u8; 32];
    let mb_hash = MBHash::encoded::<32>(
        multibase::Base::Base58Btc,
        ssi_multicodec::BLAKE3,
        byte_v.as_slice(),
    )
    .expect("pass");
    {
        let serialized = serde_json::to_string(&mb_hash).expect("pass");
        println!("MBHash serialized: {}", serialized);
        let deserialized: MBHash = serde_json::from_str(&serialized).expect("pass");
        println!("MBHash deserialized: {:?}", deserialized);
        assert_eq!(mb_hash, deserialized);
    }

    let mb_hash_str = mb_hash.as_mb_hash_str();
    {
        let serialized = serde_json::to_string(&mb_hash_str).expect("pass");
        println!("MBHashStr serialized: {}", serialized);
        let deserialized: &MBHashStr = serde_json::from_str(&serialized).expect("pass");
        println!("MBHashStr deserialized: {:?}", deserialized);
        assert_eq!(mb_hash_str, deserialized);
    }
}

#[test]
fn test_mb_hash_vectors() {
    use mbx::MBHash;

    let test_vector_v = ["zQmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"];
    for test_vector in test_vector_v {
        let mb_hash = MBHash::try_from(test_vector).expect("pass");
        let multihash = mb_hash.decoded::<64>().expect("pass");
        println!(
            "test_vector: {:?}\n    mb_hash: {:?}\n    multihash.code(): {:?}\n    multihash.size() ({} bytes): {:?}",
            test_vector,
            mb_hash,
            multihash.code(),
            multihash.size() as usize,
            multihash.digest()
        );
        #[cfg(feature = "codec-str")]
        {
            println!(
                "    codec_str(multihash.code()): {:?}",
                mbx::codec_str(multihash.code())
            );
        }
    }
}

#[test]
fn test_generate_some_hashes() {
    let message_v = vec![
        b"HIPPO".to_vec(),
        format!("HIPPO {}", rand::random::<u64>())
            .as_bytes()
            .to_vec(),
        format!("HIPPO {}", rand::random::<u64>())
            .as_bytes()
            .to_vec(),
        format!("HIPPO {}", rand::random::<u64>())
            .as_bytes()
            .to_vec(),
    ];

    #[cfg(feature = "blake3")]
    {
        for base in [
            mbx::Base::Base16Lower,
            mbx::Base::Base32Lower,
            mbx::Base::Base36Lower,
            mbx::Base::Base58Btc,
            mbx::Base::Base64Url,
        ] {
            for message in message_v.iter() {
                let mut hasher = blake3::Hasher::new();
                hasher.update(message);
                let mb_hash = mbx::MBHash::from_blake3(base, hasher);
                println!(
                    "blake3; message: {:?}, base: {:?}, mb_hash: {:?}",
                    std::str::from_utf8(message).unwrap(),
                    base,
                    mb_hash
                );
            }
        }
    }
    #[cfg(feature = "sha2")]
    {
        use digest::Digest;
        for base in [
            mbx::Base::Base16Lower,
            mbx::Base::Base32Lower,
            mbx::Base::Base36Lower,
            mbx::Base::Base58Btc,
            mbx::Base::Base64Url,
        ] {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"HIPPO");
            let mb_hash = mbx::MBHash::from_sha256(base, hasher);
            println!("sha2_256; base: {:?}, mb_hash: {:?}", base, mb_hash);
        }
        for base in [
            mbx::Base::Base16Lower,
            mbx::Base::Base32Lower,
            mbx::Base::Base36Lower,
            mbx::Base::Base58Btc,
            mbx::Base::Base64Url,
        ] {
            let mut hasher = sha2::Sha384::new();
            hasher.update(b"HIPPO");
            let mb_hash = mbx::MBHash::from_sha384(base, hasher);
            println!("sha2_384; base: {:?}, mb_hash: {:?}", base, mb_hash);
        }
        for base in [
            mbx::Base::Base16Lower,
            mbx::Base::Base32Lower,
            mbx::Base::Base36Lower,
            mbx::Base::Base58Btc,
            mbx::Base::Base64Url,
        ] {
            let mut hasher = sha2::Sha512::new();
            hasher.update(b"HIPPO");
            let mb_hash = mbx::MBHash::from_sha512(base, hasher);
            println!("sha2_512; base: {:?}, mb_hash: {:?}", base, mb_hash);
        }
    }
}

#[test]
fn test_mb_pub_key_str_decode() {
    let test_case_v = [
        // These are from:
        // - <https://github.com/w3c-ccg/did-key-spec/tree/main/test-vectors>
        // - <https://www.w3.org/TR/cid-1.0/#Multikey>

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
            ssi_multicodec::BLS12_381_G2_PUB,
            // <https://w3c-ccg.github.io/did-key-spec/#bls-12-381>
            "zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY",
        ),
        (
            ssi_multicodec::BLS12_381_G2_PUB,
            // <https://w3c-ccg.github.io/did-key-spec/#bls-12-381>
            "zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW",
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
        (
            ssi_multicodec::ED25519_PUB,
            "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu",
        ),
        // TODO: Some ed448 test vectors
        // p256
        (
            ssi_multicodec::P256_PUB,
            // <https://github.com/bshambaugh/did-key-creator>
            "zDnaeqYWNxcFqy5DcJm91BMTeWv5hjs1VL5medk9n8dDUC67T",
        ),
        (
            ssi_multicodec::P256_PUB,
            // <https://w3c-ccg.github.io/did-key-spec/#p-256>
            "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
        ),
        (
            ssi_multicodec::P256_PUB,
            // <https://w3c-ccg.github.io/did-key-spec/#p-256>
            "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
        ),
        // p384
        (
            ssi_multicodec::P384_PUB,
            // <https://github.com/bshambaugh/did-key-creator>
            "z82Lkz6GT5oNPzQowVWaYysnFPT1NAMsXayELmNjme3FhRErkTkij9ywuYWukxcLfNdW6Cw",
        ),
        (
            ssi_multicodec::P384_PUB,
            // <https://w3c-ccg.github.io/did-key-spec/#p-384>
            "z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9",
        ),
        (
            ssi_multicodec::P384_PUB,
            // <https://w3c-ccg.github.io/did-key-spec/#p-384>
            "z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54",
        ),
        // p521
        (
            ssi_multicodec::P521_PUB,
            // <https://github.com/bshambaugh/did-key-creator>
            "z2J9gaYmUxgiF1VDutBWwC4KVdpKfjnRkyV3t4kysx49eHz1wkYh1KHBPqbNdVH5GTgY2KLXtJPYTwFDkhQxuTWxK3K5HSKu",
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
        let decoded = mb_pub_key.decoded().expect("pass");
        #[cfg(feature = "codec-str")]
        {
            println!(
                "mb_pub_key: {}, decoded.codec(): {:?} (0x{:02x})",
                mb_pub_key,
                mbx::codec_str(decoded.codec()).expect("pass"),
                decoded.codec()
            );
        }
        #[cfg(not(feature = "codec-str"))]
        println!(
            "mb_pub_key: {}, decoded.codec(): 0x{:02x}",
            mb_pub_key,
            decoded.codec()
        );
        assert_eq!(decoded.codec(), codec, "multibase_str: {:?}", multibase_str);
    }
}

// Returns, for each base, the longest prefix that is common to all the generated keys.
// TODO: Priv key types too.
fn compute_mb_pub_key_longest_common_prefixes(
    key_generator: impl Fn(mbx::Base) -> mbx::MBPubKey,
) -> std::collections::BTreeMap<String, String> {
    let mut longest_common_prefix_m = std::collections::BTreeMap::new();
    let prefix_len_i = 2..=6;
    // Let's only bother with bases that are likely to be used.
    for base in [
        mbx::Base::Base32Lower,
        mbx::Base::Base58Btc,
        mbx::Base::Base64Url,
    ] {
        let mut prefix_sm = std::collections::BTreeMap::new();
        for prefix_len in prefix_len_i.clone() {
            prefix_sm.insert(prefix_len, std::collections::HashSet::new());
        }
        for _ in 0..0x100 {
            let mb_pub_key = key_generator(base);
            // println!("mb_pub_key: {}", mb_pub_key);
            for prefix_len in prefix_len_i.clone() {
                let prefix = mb_pub_key
                    .as_mb_pub_key_str()
                    .chars()
                    .take(prefix_len)
                    .collect::<String>();
                prefix_sm.get_mut(&prefix_len).unwrap().insert(prefix);
            }
        }
        // Find the longest prefix that is common to all the generated keys.
        let longest_common_prefix = prefix_sm
            .iter()
            .filter(|(_prefix_len, prefix_s)| prefix_s.len() == 1)
            .last()
            .unwrap()
            .1
            .iter()
            .next()
            .unwrap()
            .clone();
        longest_common_prefix_m.insert(format!("{:?}", base), longest_common_prefix.clone());
    }
    longest_common_prefix_m
}

fn generate_ed25519_pub_key(base: mbx::Base) -> mbx::MBPubKey {
    let mut rng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    mbx::MBPubKey::from_ed25519_dalek_verifying_key(base, &verifying_key)
}

fn test_mb_pub_key_longest_common_prefix_case(
    key_type_name: &str,
    key_generator: impl Fn(mbx::Base) -> mbx::MBPubKey,
    expected_longest_common_prefix_m: &std::collections::BTreeMap<String, String>,
) {
    let longest_common_prefix_m = compute_mb_pub_key_longest_common_prefixes(key_generator);
    println!("------------------------------------------");
    println!("key_type_name: {}", key_type_name);
    println!("longest_common_prefix_m: {:?}", longest_common_prefix_m);
    assert_eq!(longest_common_prefix_m, *expected_longest_common_prefix_m);
}

#[test]
fn test_mb_pub_key_longest_common_prefix_ed25519_dalek() {
    let mut expected_longest_common_prefix_m = std::collections::BTreeMap::new();
    expected_longest_common_prefix_m.insert("Base32Lower".to_string(), "b5ua".to_string());
    expected_longest_common_prefix_m.insert("Base58Btc".to_string(), "z6Mk".to_string());
    expected_longest_common_prefix_m.insert("Base64Url".to_string(), "u7Q".to_string());

    test_mb_pub_key_longest_common_prefix_case(
        "ed25519_dalek",
        generate_ed25519_pub_key,
        &expected_longest_common_prefix_m,
    );
}

fn generate_ed448_goldilocks_pub_key(base: mbx::Base) -> mbx::MBPubKey {
    let signing_key = ed448_goldilocks::SigningKey::generate(&mut rand_0_9::rand_core::UnwrapMut(
        &mut rand_0_9::rngs::OsRng,
    ));
    let verifying_key = signing_key.verifying_key();
    mbx::MBPubKey::from_ed448_goldilocks_verifying_key(base, &verifying_key)
}

#[test]
fn test_mb_pub_key_longest_common_prefix_ed448_goldilocks() {
    let mut expected_longest_common_prefix_m = std::collections::BTreeMap::new();
    expected_longest_common_prefix_m.insert("Base32Lower".to_string(), "bqms".to_string());
    expected_longest_common_prefix_m.insert("Base58Btc".to_string(), "z6GP".to_string());
    expected_longest_common_prefix_m.insert("Base64Url".to_string(), "ugy".to_string());

    test_mb_pub_key_longest_common_prefix_case(
        "ed448_goldilocks",
        generate_ed448_goldilocks_pub_key,
        &expected_longest_common_prefix_m,
    );
}

fn generate_p256_pub_key(base: mbx::Base) -> mbx::MBPubKey {
    let mut rng = rand::rngs::OsRng;
    let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    mbx::MBPubKey::from_p256_verifying_key(base, &verifying_key)
}

#[test]
fn test_mb_pub_key_longest_common_prefix_p256() {
    let mut expected_longest_common_prefix_m = std::collections::BTreeMap::new();
    expected_longest_common_prefix_m.insert("Base32Lower".to_string(), "bqasa".to_string());
    expected_longest_common_prefix_m.insert("Base58Btc".to_string(), "zDnae".to_string());
    expected_longest_common_prefix_m.insert("Base64Url".to_string(), "ugCQ".to_string());

    test_mb_pub_key_longest_common_prefix_case(
        "p256",
        generate_p256_pub_key,
        &expected_longest_common_prefix_m,
    );
}

fn generate_p384_pub_key(base: mbx::Base) -> mbx::MBPubKey {
    let mut rng = rand::rngs::OsRng;
    let signing_key = p384::ecdsa::SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    mbx::MBPubKey::from_p384_verifying_key(base, &verifying_key)
}

#[test]
fn test_mb_pub_key_longest_common_prefix_p384() {
    let mut expected_longest_common_prefix_m = std::collections::BTreeMap::new();
    expected_longest_common_prefix_m.insert("Base32Lower".to_string(), "bqesa".to_string());
    expected_longest_common_prefix_m.insert("Base58Btc".to_string(), "z82L".to_string());
    expected_longest_common_prefix_m.insert("Base64Url".to_string(), "ugSQ".to_string());

    test_mb_pub_key_longest_common_prefix_case(
        "p384",
        generate_p384_pub_key,
        &expected_longest_common_prefix_m,
    );
}

fn generate_p521_pub_key(base: mbx::Base) -> mbx::MBPubKey {
    let signing_key = p521::ecdsa::SigningKey::random(&mut rand_0_9::rand_core::UnwrapMut(
        &mut rand_0_9::rngs::OsRng,
    ));
    let verifying_key = signing_key.verifying_key();
    mbx::MBPubKey::from_p521_verifying_key(base, &verifying_key)
}

#[test]
fn test_mb_pub_key_longest_common_prefix_p521() {
    let mut expected_longest_common_prefix_m = std::collections::BTreeMap::new();
    expected_longest_common_prefix_m.insert("Base32Lower".to_string(), "bqisa".to_string());
    expected_longest_common_prefix_m.insert("Base58Btc".to_string(), "z2J9g".to_string());
    expected_longest_common_prefix_m.insert("Base64Url".to_string(), "ugiQ".to_string());

    test_mb_pub_key_longest_common_prefix_case(
        "p521",
        generate_p521_pub_key,
        &expected_longest_common_prefix_m,
    );
}

fn generate_secp256k1_pub_key(base: mbx::Base) -> mbx::MBPubKey {
    let mut rng = rand::rngs::OsRng;
    let signing_key = k256::ecdsa::SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    mbx::MBPubKey::from_k256_verifying_key(base, &verifying_key)
}

#[test]
fn test_mb_pub_key_longest_common_prefix_secp256k1() {
    let mut expected_longest_common_prefix_m = std::collections::BTreeMap::new();
    expected_longest_common_prefix_m.insert("Base32Lower".to_string(), "b44aq".to_string());
    expected_longest_common_prefix_m.insert("Base58Btc".to_string(), "zQ3sh".to_string());
    expected_longest_common_prefix_m.insert("Base64Url".to_string(), "u5wE".to_string());

    test_mb_pub_key_longest_common_prefix_case(
        "secp256k1",
        generate_secp256k1_pub_key,
        &expected_longest_common_prefix_m,
    );
}
