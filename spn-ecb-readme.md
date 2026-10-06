## 1. Substitution-permutation network (SPN)

An SPN is a design for block ciphers. The plaintext block goes through several **rounds**, and every round does three things:

1. **Key mixing**: XOR the block with a round key.
2. **Substitution**: replace small pieces of the block (here: bytes) using an S-box lookup table.
3. **Permutation**: shuffle the bit positions of the whole block.

The S-box gives **confusion** (the link between key and ciphertext is hidden) and the permutation gives **diffusion** (a change in one input bit spreads to many output bits). These two ideas come from Claude Shannon's 1949 paper on secrecy systems. After enough rounds, changing one bit of the plaintext changes about half of the ciphertext bits.

**Decryption** runs the same steps backwards: undo the final XOR, then in reverse round order undo the permutation, apply the inverse S-box, and XOR with the same round key again. This works because every step is reversible (the S-box is one-to-one, the permutation is a bijection, and XOR with the same value twice cancels out).

AES is the best-known SPN. Our cipher keeps the same round skeleton in a much simpler form.

Source:
- https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network - overview of SPNs, rounds, S-boxes, P-boxes and round keys

## 2. The S-box (from AES)

An S-box is a table that maps each possible byte (0-255) to another byte. We use the real AES S-box, so for example `0x00` becomes `0x63` and `0x53` becomes `0xED`.

The AES S-box is built in two steps for every byte value:
1. Take its multiplicative inverse in the finite field GF(2^8) (the byte `0x00` is mapped to itself).
2. Apply a fixed affine transformation (a bit mixing step plus XOR with the constant `0x63`).

The inverse step makes the table highly non-linear, and the affine step removes simple fixed points. Because the table is one-to-one, an inverse S-box exists and is used for decryption.

Sources:
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf - FIPS 197, the official AES standard (S-box in section 5.1.1)
- https://en.wikipedia.org/wiki/Rijndael_S-box - readable explanation of how the S-box is built

## 3. Bit permutation and round keys (our simple choices)

These two parts are our own simple design for the demo, not taken from a standard.

- **Permutation layer**: bit number `i` of the 128-bit block moves to position `(7 * i) mod 128`. Since 7 and 128 share no common divisor, every bit gets a different position, so the shuffle can be reversed by using the multiplier 55 (because 7 * 55 = 385 = 3 * 128 + 1, so 55 is the inverse of 7 modulo 128). The eight bits of one byte land in different bytes, which spreads the effect of every S-box.
- **Round keys**: round key `r` is the 128-bit key rotated left by `r` bytes and XORed with the number `r`. That gives 11 round keys: one for each of the 10 rounds and one for the final XOR. Real ciphers use stronger key schedules (AES uses key expansion with S-boxes and round constants), but this simple version is enough to show the idea of "different key in every round".

## 4. ECB mode (Electronic Codebook)

A block cipher only encrypts one fixed-size block (16 bytes here). A **mode of operation** says how to encrypt a longer message. In ECB the message is split into blocks and **every block is encrypted separately with the same key**. Decryption does the same per block.

Properties:
- Simple and parallelizable.
- **Identical plaintext blocks give identical ciphertext blocks**, so patterns in the data stay visible. This is why ECB is not recommended for real use, and it is a good thing to point out in a demo (try encrypting `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`: the two ciphertext blocks are equal).

Sources:
- https://csrc.nist.gov/pubs/sp/800/38/a/final - NIST SP 800-38A, the standard describing block cipher modes (ECB is in section 6.1)
- https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB) - ECB explained, including the pattern weakness

## 5. Padding (PKCS#7)

The message length is rarely a multiple of 16 bytes, so it has to be filled up. PKCS#7 adds `N` bytes, each with the value `N`, where `N` is the number of missing bytes (1 to 16).

Examples for a 16-byte block:
- 11 bytes of data -> add 5 bytes of `0x05`
- 15 bytes of data -> add 1 byte of `0x01`
- 16 bytes of data -> add a whole extra block of 16 bytes of `0x10` (so padding is always present and can always be removed)

After decryption, the last byte tells how many bytes to remove. If the padding looks wrong, decryption fails, which in our demo usually means the wrong key was entered.

Source:
- https://datatracker.ietf.org/doc/html/rfc5652#section-6.3 - RFC 5652 (CMS), section 6.3 defines this padding method

## 6. Base64 output

Ciphertext is arbitrary bytes, which is unreadable and hard to copy in a terminal. Base64 turns every 3 bytes into 4 printable characters (`A-Z a-z 0-9 + /`, with `=` as filler at the end). It is not encryption, only a text representation.

Source:
- https://datatracker.ietf.org/doc/html/rfc4648 - RFC 4648, the Base64 specification

## Usage

```
python spn_ecb.py
```

Choose 1 to encrypt or 2 to decrypt, then enter a key of exactly 16 characters (16 bytes = 128 bits) and the message or Base64 ciphertext.

## Limitations (good to mention to the professor)

- ECB leaks patterns (section 4).
- The key schedule is a simple rotation, so related round keys make the cipher much weaker than AES.
- The permutation is a fixed bit shuffle without a mixing step like AES MixColumns.
- No authentication: nobody can tell if the ciphertext was modified.

## References

1. NIST, FIPS 197: Advanced Encryption Standard (AES) - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
2. NIST SP 800-38A: Block Cipher Modes of Operation - https://csrc.nist.gov/pubs/sp/800/38/a/final
3. RFC 5652, Cryptographic Message Syntax (padding) - https://datatracker.ietf.org/doc/html/rfc5652
4. RFC 4648, Base16, Base32, Base64 encodings - https://datatracker.ietf.org/doc/html/rfc4648
5. Wikipedia, Substitution-permutation network - https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network
6. Wikipedia, Rijndael S-box - https://en.wikipedia.org/wiki/Rijndael_S-box
7. C. Shannon, "Communication Theory of Secrecy Systems", Bell System Technical Journal, 1949 (confusion and diffusion; paper only, no link)
