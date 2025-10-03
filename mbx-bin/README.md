# mbx-bin

CLI tool for computing `MBHash` values and decoding `MBHash`, `MBPubKey`, and `MBPrivKey` values.

## Installation

From the `mbx-bin` directory, run:

```bash
cargo install --path . --all-features
```

## Usage

### Hashing

Default hash function is `blake3`, default base is `base64url`.  Note that the `-n` option for `echo` is required to avoid adding a trailing newline to the input.

```bash
echo -n "HIPPO" | mbx hash
```

Output is:

```
uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA
```

Base can be changed with the `--base` option.

```bash
echo -n "HIPPO" | mbx hash --base base32lower
```

Output is:

```
bdyqeuhmvatohdzlbzsksax5phzwrpa55n6ujswwyxvhbs4omjcxa2ea
```

Hash function can be changed with the `--hash-function` option.

```bash
echo -n "HIPPO" | mbx hash --hash-function sha2-256
```

Output is:

```
uEiAWCleApqPkQg-DKbql-C5OOyZ7ydUgq7G_rHepYEukHg
```

### Decoding

Default base for displaying decoded bytes is `base16lower`.

```bash
echo uEiAWCleApqPkQg-DKbql-C5OOyZ7ydUgq7G_rHepYEukHg | mbx decode
```

Output is:

```
MBHash in Base64Url with codec SHA2_256 (0x12); 32 digest bytes shown here in Base16Lower: 160a5780a6a3e4420f8329baa5f82e4e3b267bc9d520abb1bfac77a9604ba41e
```

Note that the base for displaying decoded bytes can be changed with the `--base` option.

```bash
echo uEiAWCleApqPkQg-DKbql-C5OOyZ7ydUgq7G_rHepYEukHg | mbx decode --base base32lower
```

Output is:

```
MBHash in Base64Url with codec SHA2_256 (0x12); 32 digest bytes shown here in Base32Lower: cyffpafgupseed4dfg5kl6bojy5sm66j2uqkxmn7vr32sycluqpa
```

## To-dos

-   Maybe print the output of `decode` as JSON so it's structured.
