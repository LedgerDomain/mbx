# mbx

This Rust crate provides ergonomic types for working with strings that are multibase-encoded multihash and multikey values.  Versions of each type are provided that are analogous to the `String` and `str` types, with analogous semantics.

## Codec Categories

A "codec" refers to an entry in the [multicodec registry](https://github.com/multiformats/multicodec/blob/master/table.csv).

This crate provides a `CodecCategory` enum that represents a categorization of relevant codecs.  Note that this is not a standard categorization, doesn't guarantee to be complete, but it does accurately categorize the most common codecs.

## Available Types

### `MBHash` and `MBHashStr`

The `MBHash` and `MBHashStr` types are newtype wrappers around `String` and `str`, respectively, where the string content is a multibase-encoded multihash.  The anatomy of the string is as follows.  Given a base-encoding `B`, a multihash codec `C`, a digest length `L`, and digest bytes `D`, the string is of the form:

    PrefixCharFor(B) || Multibase(B, Multihash(C, L, D))

where `Multihash(C, L, D)` is defined to be the bytes (where `||` denotes byte array concatenation):

    VarInt(C) || VarInt(L) || D

where `VarInt(N)` is defined to be the unsigned varint encoding of the integer `N`.

The codec is limited to be one having the `multihash` tag in the multicodec table.

Examples:
-   `uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA` : A `blake3` hash in `base64url` encoding.
-   `f1e204a1d9504dc71e561cc95205faf3e6d1783bd6fa8995ad8bd4e1971cc48ae0d10` : A `blake3` hash in `base16lower` encoding.
-   `uEiAWCleApqPkQg-DKbql-C5OOyZ7ydUgq7G_rHepYEukHg` : A `sha2-256` hash in `base64url` encoding.
-   `zQmPpgppLtSyUF2qkWn648Hs6MFBuRU8Xg8LiaY2jf31iGM` : A `sha2-256` hash in `base58btc` encoding.

References:
-   https://github.com/multiformats/multihash
-   https://www.w3.org/TR/cid-1.0/#multihash
-   https://github.com/multiformats/multicodec/blob/master/table.csv
-   https://github.com/multiformats/unsigned-varint

### `MBPubKey` and `MBPubKeyStr`

The `MBPubKey` and `MBPubKeyStr` types are newtype wrappers around `String` and `str`, respectively, where the string content is a multibase-encoded multikey.  The anatomy of the string is as follows.  Given a base-encoding `B`, a multikey codec `C`, and public key bytes `D`, the string is of the form (where `||` denotes string/byte array concatenation):

    PrefixCharFor(B) || Multibase(B, VarInt(C) || D)

The allowable codec values are the subset of those having the `key` tag in the multicodec table, which denote a public key type.

Examples:
-   `z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp` : An `ed25519` public key in `base58btc` encoding.  Note that this is the format used in the did:key DID method as the DID-method-specific identifier.
-   `u7QHumXvEpaKqvVb0DYhWrsC0z3p-3l_l7R9XM5fxqEW02Q` : An `ed25519` public key in `base64url` encoding.

References:
-   https://www.w3.org/TR/cid-1.0/#multikey
-   https://github.com/multiformats/multicodec/blob/master/table.csv
-   https://github.com/multiformats/unsigned-varint

### `MBPrivKey` and `MBPrivKeyStr`

The `MBPrivKey` and `MBPrivKeyStr` types are analogous to `MBPubKey` and `MBPubKeyStr`, respectively, and have the same definition, except that the codec is limited to 

    PrefixCharFor(B) || Multibase(B, VarInt(C) || D)

The allowable codec values are the subset of those having the `key` tag in the multicodec table, which denote a private key type.

## License

[MIT License](LICENSE).

## To-dos

-   When v0.14 is released for `ed448-goldilocks`, `k256`, `p256`, `p384`, and `p521`, add support for them.  Similarly, for whatever version of `ed25519-dalek` supports v3 version of crate `signature`.
-   Potentially add support for different versions of the various crates (e.g. `ed25519-dalek`, `ed448-goldilocks`, `k256`, `p256`, `p384`, `p521`), with features called `ed25519-dalek-v3`, `k256-v0.14`, etc.
-   Add prefix-based checks for `key_type` in `MBPrivKeyStr` and `MBPubKeyStr` to avoid allocations.
