use std::io::{Read, Write};

/// CLI tool for mbx.
#[derive(clap::Parser)]
#[clap(version, about)]
enum CLI {
    /// Decode a `MBHash`, `MBPubKey`, or `MBPrivKey` from stdin.  Outputs the kind, base, codec, and decoded bytes.
    /// See <https://github.com/multiformats/multicodec/blob/master/table.csv> for the table of codecs.
    Decode(Decode),
    /// Read from stdin, compute its hash, and print the MBHash-formatted value using the specified base and hash function.
    Hash(Hash),
}

impl CLI {
    fn handle(self) {
        match self {
            Self::Decode(x) => x.handle(),
            Self::Hash(x) => x.handle(),
        }
    }
}

fn base_from_str(s: &str) -> Result<mbx::Base, mbx::Error> {
    let s = s.to_lowercase();
    match s.as_str() {
        "identity" => Err(mbx::error!("base `identity` is not supported")),
        "base2" => Ok(mbx::Base::Base2),
        "base8" => Ok(mbx::Base::Base8),
        "base10" => Ok(mbx::Base::Base10),
        "base16lower" => Ok(mbx::Base::Base16Lower),
        "base16upper" => Ok(mbx::Base::Base16Upper),
        "base32lower" => Ok(mbx::Base::Base32Lower),
        "base32upper" => Ok(mbx::Base::Base32Upper),
        "base32padlower" => Ok(mbx::Base::Base32PadLower),
        "base32padupper" => Ok(mbx::Base::Base32PadUpper),
        "base32hexlower" => Ok(mbx::Base::Base32HexLower),
        "base32hexupper" => Ok(mbx::Base::Base32HexUpper),
        "base32hexpadlower" => Ok(mbx::Base::Base32HexPadLower),
        "base32hexpadupper" => Ok(mbx::Base::Base32HexPadUpper),
        "base32z" => Ok(mbx::Base::Base32Z),
        "base36lower" => Ok(mbx::Base::Base36Lower),
        "base36upper" => Ok(mbx::Base::Base36Upper),
        "base58flickr" => Ok(mbx::Base::Base58Flickr),
        "base58btc" => Ok(mbx::Base::Base58Btc),
        "base64" => Ok(mbx::Base::Base64),
        "base64pad" => Ok(mbx::Base::Base64Pad),
        "base64url" => Ok(mbx::Base::Base64Url),
        "base64urlpad" => Ok(mbx::Base::Base64UrlPad),
        "base256emoji" => Ok(mbx::Base::Base256Emoji),
        _ => Err(mbx::error!(
            "Invalid base: {}; supported bases are: base2, base8, base10, base16lower, base16upper, base32lower, base32upper, base32padlower, base32padupper, base32hexlower, base32hexupper, base32hexpadlower, base32hexpadupper, base32z, base36lower, base36upper, base58flickr, base58btc, base64, base64pad, base64url, base64urlpad, base256emoji",
            s
        )),
    }
}

#[allow(non_camel_case_types)]
#[derive(clap::ValueEnum, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HashFunction {
    Blake3,
    Sha_224,
    Sha_256,
    Sha_384,
    Sha_512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashFunction {
    fn new_hasher(&self) -> Hasher {
        match self {
            HashFunction::Blake3 => Hasher::Blake3(blake3::Hasher::new()),
            HashFunction::Sha_224 => Hasher::Sha_224(sha2::Sha224::default()),
            HashFunction::Sha_256 => Hasher::Sha_256(sha2::Sha256::default()),
            HashFunction::Sha_384 => Hasher::Sha_384(sha2::Sha384::default()),
            HashFunction::Sha_512 => Hasher::Sha_512(sha2::Sha512::default()),
            HashFunction::Sha3_224 => Hasher::Sha3_224(sha3::Sha3_224::default()),
            HashFunction::Sha3_256 => Hasher::Sha3_256(sha3::Sha3_256::default()),
            HashFunction::Sha3_384 => Hasher::Sha3_384(sha3::Sha3_384::default()),
            HashFunction::Sha3_512 => Hasher::Sha3_512(sha3::Sha3_512::default()),
        }
    }
}

impl Default for HashFunction {
    fn default() -> Self {
        Self::Blake3
    }
}

#[allow(non_camel_case_types)]
pub enum Hasher {
    Blake3(blake3::Hasher),
    Sha_224(sha2::Sha224),
    Sha_256(sha2::Sha256),
    Sha_384(sha2::Sha384),
    Sha_512(sha2::Sha512),
    Sha3_224(sha3::Sha3_224),
    Sha3_256(sha3::Sha3_256),
    Sha3_384(sha3::Sha3_384),
    Sha3_512(sha3::Sha3_512),
}

impl Hasher {
    fn update(&mut self, data: &[u8]) {
        use digest::Digest;
        match self {
            Hasher::Blake3(hasher) => {
                hasher.update(data);
            }
            Hasher::Sha_224(hasher) => hasher.update(data),
            Hasher::Sha_256(hasher) => hasher.update(data),
            Hasher::Sha_384(hasher) => hasher.update(data),
            Hasher::Sha_512(hasher) => hasher.update(data),
            Hasher::Sha3_224(hasher) => hasher.update(data),
            Hasher::Sha3_256(hasher) => hasher.update(data),
            Hasher::Sha3_384(hasher) => hasher.update(data),
            Hasher::Sha3_512(hasher) => hasher.update(data),
        }
    }
    fn into_mb_hash(self, base: mbx::Base) -> mbx::MBHash {
        match self {
            Hasher::Blake3(hasher) => mbx::MBHash::from_blake3(base, hasher),
            Hasher::Sha_224(hasher) => mbx::MBHash::from_sha224(base, hasher),
            Hasher::Sha_256(hasher) => mbx::MBHash::from_sha256(base, hasher),
            Hasher::Sha_384(hasher) => mbx::MBHash::from_sha384(base, hasher),
            Hasher::Sha_512(hasher) => mbx::MBHash::from_sha512(base, hasher),
            Hasher::Sha3_224(hasher) => mbx::MBHash::from_sha3_224(base, hasher),
            Hasher::Sha3_256(hasher) => mbx::MBHash::from_sha3_256(base, hasher),
            Hasher::Sha3_384(hasher) => mbx::MBHash::from_sha3_384(base, hasher),
            Hasher::Sha3_512(hasher) => mbx::MBHash::from_sha3_512(base, hasher),
        }
    }
}

#[derive(clap::Args)]
struct Decode {
    /// If specified, don't print a trailing newline in the output [default: print newline].
    #[arg(short, long)]
    no_newline: bool,
    /// The base to use for the decoded value.  Possible values are: identity, base2, base8, base10,
    /// base16lower, base16upper, base32lower, base32upper, base32padlower, base32padupper,
    /// base32hexlower, base32hexupper, base32hexpadlower, base32hexpadupper, base32z, base36lower,
    /// base36upper, base58flickr, base58btc, base64, base64pad, base64url, base64urlpad, base256emoji.
    #[arg(short, long, default_value = "base16lower", value_parser = base_from_str)]
    base: mbx::Base,
    /// If specified, show the bytes of the decoded value.  Default is to redact the bytes.
    #[arg(short, long, default_value = "false")]
    show_priv_key_bytes: bool,
}

impl Decode {
    fn handle(self) {
        // Read all of stdin into a String.
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let input = input.trim();

        let base: mbx::Base = self.base.into();

        // Decode the value and print the result.
        // TODO: Maybe print this as JSON so it's structured.
        if let Ok(hash) = mbx::MBHashStr::new_ref(input) {
            let multihash = hash.decoded::<64>().unwrap();
            std::io::stdout()
                .write_fmt(format_args!(
                    "MBHash in {:?} with codec {} (0x{:02x}); {} digest bytes shown here in {:?}: {}",
                    hash.base(),
                    mbx::codec_str(multihash.code()).unwrap_or("UnknownCodec"),
                    multihash.code(),
                    multihash.digest().len(),
                    base,
                    base.encode(multihash.digest())
                ))
                .unwrap();
        } else if let Ok(pub_key) = mbx::MBPubKeyStr::new_ref(input) {
            let multiencoded = pub_key.decoded().unwrap();
            std::io::stdout()
                .write_fmt(format_args!(
                    "MBPubKey in {:?} with codec {} (0x{:02x}); bytes shown here in {:?}: {}",
                    pub_key.base(),
                    mbx::codec_str(multiencoded.codec()).unwrap_or("UnknownCodec"),
                    multiencoded.codec(),
                    base,
                    base.encode(multiencoded.data())
                ))
                .unwrap();
        } else if let Ok(priv_key) = mbx::MBPrivKeyStr::new_ref(input) {
            let multiencoded = priv_key.decoded().unwrap();
            std::io::stdout()
                .write_fmt(format_args!(
                    "MBPrivKey in {:?} with codec {} (0x{:02x}); bytes shown here in {:?}: {}",
                    priv_key.base(),
                    mbx::codec_str(multiencoded.codec()).unwrap_or("UnknownCodec"),
                    multiencoded.codec(),
                    base,
                    if self.show_priv_key_bytes {
                        base.encode(multiencoded.data())
                    } else {
                        "<REDACTED>".to_string()
                    }
                ))
                .unwrap();
        } else {
            eprintln!("Unrecognized input");
            std::process::exit(1);
        }

        // Print the optional newline.
        if !self.no_newline {
            std::io::stdout().write("\n".as_bytes()).unwrap();
        }
    }
}

#[derive(clap::Args)]
struct Hash {
    /// If specified, don't print a trailing newline in the output [default: print newline].
    #[arg(short, long)]
    no_newline: bool,
    /// The base to use for the hash.  Possible values are: base2, base8, base10, base16lower,
    /// base16upper, base32lower, base32upper, base32padlower, base32padupper, base32hexlower,
    /// base32hexupper, base32hexpadlower, base32hexpadupper, base32z, base36lower, base36upper,
    /// base58flickr, base58btc, base64, base64pad, base64url, base64urlpad, base256emoji.
    #[arg(short, long, default_value = "base64url", value_parser = base_from_str)]
    base: mbx::Base,
    /// The hash function to use.  Note that sha-224, sha-256, sha-384, and sha-512 are all
    /// part of the SHA-2 family of hash functions.
    #[arg(short = 'f', long, default_value = "blake3")]
    hash_function: HashFunction,
}

impl Hash {
    fn handle(self) {
        let base = self.base.into();

        // Create the appropriate hasher.
        let mut hasher = self.hash_function.new_hasher();
        // Feed all of stdin into the hasher, using a buffer of a fixed size.
        {
            let mut buffer = [0u8; 1024];
            loop {
                let n = std::io::stdin().read(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
        }
        // Compute the hash.
        let hash = hasher.into_mb_hash(base);

        // Print the hash and optional newline.
        std::io::stdout().write(hash.as_bytes()).unwrap();
        if !self.no_newline {
            std::io::stdout().write("\n".as_bytes()).unwrap();
        }
    }
}

fn main() {
    use clap::Parser;
    CLI::parse().handle();
}
