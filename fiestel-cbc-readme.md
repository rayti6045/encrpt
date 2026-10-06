# Feistel Block Cipher in CBC Mode — Algorithm Description

This document explains the **algorithms and standards** that the cipher is built from — not the Python code itself. Every section lists its sources; the same sources are referenced in the code comments of `feistel_cbc.py`.

> **Educational project.** This is a learning exercise and must not be used to protect real data (see [Security notes](#9-security-notes)).

## 1. Overview

The program turns a text message and a 16-character key into Base64 ciphertext. It combines six well-known building blocks:

| Stage | Algorithm | Purpose |
|---|---|---|
| 1 | **PKCS#7 padding** | make the message length a multiple of the 16-byte block size |
| 2 | **Random IV** | give every message a fresh starting value for chaining |
| 3 | **CBC mode** | chain the blocks so that each ciphertext block depends on all previous blocks |
| 4 | **Feistel network** (12 rounds, 128-bit block) | the block cipher that encrypts one block |
| 5 | **AES S-box** + byte permutation (inside the round function) | provide confusion and diffusion |
| 6 | **Base64** | represent the binary result (IV + ciphertext) as printable text |

Alongside these, a small **key schedule** (custom, built from AES ideas) produces one subkey per round.

```
plaintext ─► PKCS#7 padding ─► split into 16-byte blocks ─► CBC chaining with Feistel cipher (IV first) ─► Base64(IV + ciphertext)
```

## 2. Block ciphers and modes of operation

A **block cipher** is a keyed function that encrypts a fixed-size block of data (here 128 bits) and can be reversed with the same key: `C = E_K(P)` and `P = D_K(C)`. Messages are almost never exactly one block long, so two additional things are needed: a **padding scheme** (Section 6) and a **mode of operation** (Section 5) that says how to apply the block cipher to many blocks.

Sources:
- <https://en.wikipedia.org/wiki/Block_cipher> — block ciphers in general
- <https://csrc.nist.gov/pubs/sp/800/38/a/final> — NIST SP 800-38A, the standard that defines the classic modes of operation (ECB, CBC, CFB, OFB, CTR)

## 3. Feistel network

### What it is

A Feistel network is a general way to build a block cipher out of a **round function F** that does not need to be invertible. It was introduced by Horst Feistel at IBM in the early 1970s and is the structure of DES.

The block is split into a left half `L` and a right half `R`. Each round `i` uses its own subkey `K_i`:

```
L(i+1) = R(i)
R(i+1) = L(i) XOR F( R(i), K(i) )
```

```
        L_i                     R_i
         |                       |
         |                       +----------------+
         |                       |                |
         |                 +-----v------+         |
         |                 | F(R_i,K_i) |         |
         |                 +-----+------+         |
         |                       |                |
         +---------------------> XOR              |
                                  |               |
                                  v               v
                              R_(i+1)          L_(i+1)
```

After the last round the two halves are swapped once more, so the final output is `R_n || L_n`.

### Why it is invertible

Given `(L(i+1), R(i+1))` one recovers the previous round by

```
R(i)  = L(i+1)
L(i)  = R(i+1) XOR F( L(i+1), K(i) )
```

This only needs to *evaluate* F, never to invert it. Consequently **decryption is the same network with the subkeys used in reverse order** (`K_n … K_1`). This is the main practical advantage of the design: one implementation serves both directions, and F can be any (even non-invertible) function.

### Parameters in this project

- Block size: **128 bits** (two 64-bit halves of 8 bytes), the same block size as AES.
- Rounds: **12** (own choice; DES uses 16).
- Round function: key XOR → AES S-box → byte rotation (Section 4).

Sources:
- <https://en.wikipedia.org/wiki/Feistel_cipher> — construction, encryption/decryption equations, final swap
- <https://cacr.uwaterloo.ca/hac/about/chap7.pdf> — A. Menezes, P. van Oorschot, S. Vanstone, *Handbook of Applied Cryptography*, Chapter 7 (block ciphers), Section 7.4.1 on Feistel ciphers
- H. Feistel, "Cryptography and Computer Privacy", *Scientific American* 228(5), May 1973, pp. 15–23 — the original description
- <https://en.wikipedia.org/wiki/Data_Encryption_Standard> — DES, the best-known Feistel cipher

## 4. The round function: confusion, diffusion and the AES S-box

Claude Shannon (1949) named two properties that a good cipher needs:

- **Confusion** — the relationship between key and ciphertext should be complex. Achieved here by the **S-box**.
- **Diffusion** — every input bit should influence many output bits. Achieved here by a **byte permutation** (rotation), repeated over many rounds.

The round function therefore performs three steps:

1. **Key mixing** — XOR the 8-byte half with the 8-byte round subkey (in AES this step is called *AddRoundKey*).
2. **Substitution** — replace every byte by its entry in the S-box (in AES: *SubBytes*).
3. **Permutation** — rotate the 8 bytes by 3 positions (AES uses the similar *ShiftRows* operation; the exact rotation here is an own choice).

### The AES S-box

The S-box is a fixed table of 256 bytes. It is a **bijection** (every byte value appears exactly once) and is built mathematically:

1. Take the byte as an element of the finite field GF(2⁸) (modulo the polynomial x⁸ + x⁴ + x³ + x + 1).
2. Replace it by its **multiplicative inverse** in that field (0 maps to 0). The inverse function is highly non-linear.
3. Apply a fixed **affine transformation** over GF(2) and add the constant `0x63`, which removes fixed points and simple algebraic structure.

Examples: `S(0x00) = 0x63`, `S(0x01) = 0x7c`, `S(0x53) = 0xed`. The table used in the code is copied from the AES standard (and was cross-checked by regenerating it from the definition above).

Sources:
- <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf> — FIPS 197 (AES standard), Sections 5.1.1 (SubBytes, S-box table), 5.1.2 (ShiftRows), 5.1.4 (AddRoundKey)
- <https://en.wikipedia.org/wiki/Rijndael_S-box> — construction and properties of the S-box
- <https://en.wikipedia.org/wiki/Confusion_and_diffusion> — Shannon's confusion and diffusion
- C. E. Shannon, "Communication Theory of Secrecy Systems", *Bell System Technical Journal* 28(4), 1949 — <https://ieeexplore.ieee.org/document/6769090>
- <https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network> — substitution + permutation layers, the design principle behind AES

## 5. CBC mode (Cipher Block Chaining) and the IV

### What it is

In **CBC** every plaintext block is XORed with the previous ciphertext block *before* it is encrypted. This links all blocks together: a ciphertext block depends on its own plaintext block and on every block before it. The first block has no predecessor, so an **initialization vector (IV)** of one block size is used in its place (`C_0 = IV`).

```
Encryption:  C_0 = IV
             C_i = E_K( P_i XOR C_(i-1) )

Decryption:  P_i = D_K( C_i ) XOR C_(i-1)
```

```
 IV ─┐          ┌──────────┐          ┌──────────┐
     ▼          │          ▼          │          ▼
P_1 ─► XOR      │   P_2 ─► XOR        │   P_3 ─► XOR
        │       │          │          │          │
      E_K       │        E_K          │        E_K
        │       │          │          │          │
        ├───────┘          ├──────────┘          │
        ▼                  ▼                     ▼
       C_1                C_2                   C_3
```

### The initialization vector

- The IV must be **unpredictable** (fresh random value for every message) and must never be reused with the same key for different messages.
- The IV is **not secret**. The receiver needs it, so it is sent together with the ciphertext. In this project the output is `IV || C_1 || C_2 || …` encoded as Base64, and the receiver takes the first 16 bytes as the IV.
- The IV comes from the operating system's cryptographically secure random generator.

### Properties

- **Identical plaintext blocks produce different ciphertext blocks**, and the same message encrypted twice gives different results (because of the random IV). This fixes the main weakness of ECB, where patterns in the data stay visible.
- Encryption is **sequential** (block `i` needs block `i−1`), but decryption can be done in parallel because every `C_(i−1)` is already known.
- **Error propagation:** a flipped bit in `C_i` corrupts all of `P_i` and flips the same bit in `P_(i+1)`; later blocks are unaffected.
- **No integrity protection:** an attacker who can modify ciphertext can predictably flip bits of the next plaintext block (at the price of garbling one block), and CBC with padding can be attacked through *padding oracles* if the receiver reveals whether padding was valid. In practice CBC must be combined with a MAC or replaced by an authenticated mode.

Sources:
- <https://csrc.nist.gov/pubs/sp/800/38/a/final> — NIST SP 800-38A, Section 6.2: official definition of CBC; Appendix C covers IV generation
- <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)> — CBC explained with diagrams, properties and error propagation
- <https://docs.python.org/3/library/os.html#os.urandom> — `os.urandom`, the OS source of random bytes used for the IV
- <https://en.wikipedia.org/wiki/Padding_oracle_attack> — attack on CBC with padding that motivates the integrity warning

## 6. Padding: PKCS#7

A block cipher works on whole blocks, so the message length must be a multiple of the block size. **PKCS#7** padding appends `N` bytes, each with the value `N`, where `N = block_size − (length mod block_size)`. With a 16-byte block, `N` is always between 1 and 16:

| Message length (bytes) | Padding appended |
|---|---|
| 11 | `05 05 05 05 05` |
| 15 | `01` |
| 16 (already full) | a whole extra block of sixteen `10` bytes |

Padding is **always** added, even when the message already fills the last block, so that the receiver can unambiguously remove it: it reads the last byte `N`, checks that the last `N` bytes all equal `N`, and discards them. If the check fails, the padding (or the key/ciphertext) is invalid.

Sources:
- <https://datatracker.ietf.org/doc/html/rfc5652#section-6.3> — RFC 5652 (Cryptographic Message Syntax), Section 6.3: the padding rule
- <https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7> — PKCS#5/PKCS#7 padding with examples

## 7. Key schedule and Base64

### Key schedule

Each Feistel round needs its own subkey. A **key schedule** derives all round keys from the one master key. AES expands its key by repeating three operations (**RotWord** – rotate bytes, **SubWord** – pass bytes through the S-box, **Rcon** – XOR a round-dependent constant).

The schedule in this project is a **simplified custom design** (not a standard) that reuses those ideas: the two 8-byte halves of the 16-byte key are XORed together; then, for each round, the value is rotated by one byte, passed through the S-box, and its first byte is XORed with the round number. The result is the 8-byte subkey for that round and the starting value for the next one.

Sources:
- <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf> — FIPS 197, Section 5.2 (Key Expansion): RotWord, SubWord, Rcon
- <https://en.wikipedia.org/wiki/Rijndael_key_schedule> — the AES key schedule step by step
- <https://en.wikipedia.org/wiki/Key_schedule> — key schedules in general

### Base64

The result (IV followed by ciphertext) is arbitrary binary data, which cannot be reliably printed or copied. **Base64** encodes every 3 bytes (24 bits) as 4 printable characters (6 bits each) from the alphabet `A–Z a–z 0–9 + /`, with `=` used as padding at the end. It is only an encoding, not encryption; it adds no security and is fully reversible without a key.

Sources:
- <https://datatracker.ietf.org/doc/html/rfc4648#section-4> — RFC 4648, Section 4: Base64 encoding
- <https://en.wikipedia.org/wiki/Base64> — overview

## 8. Comparison with ECB

| | ECB | CBC |
|---|---|---|
| Block encryption | `C_i = E_K(P_i)` | `C_i = E_K(P_i XOR C_(i-1))` |
| IV needed | no | yes, random per message |
| Same plaintext block → same ciphertext block | yes (leaks patterns) | no |
| Same message twice → same output | yes | no (new IV each time) |
| Encryption parallelizable | yes | no |
| Decryption parallelizable | yes | yes |
| Output size | padded message | 16 bytes (IV) + padded message |

Source: <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation> — comparison of the modes of operation

## 9. Security notes

- The **Feistel structure, S-box, CBC, PKCS#7 and Base64** are standard, documented techniques. The **round function details and the key schedule are custom**, and have not been analysed by cryptographers. Home-made ciphers should never be trusted; real systems use AES with an authenticated mode such as GCM.
- CBC hides repeated plaintext blocks, but it provides **no authentication**: tampered ciphertext is not reliably detected, and padding errors can leak information (padding oracle attacks).
- The IV must be random for every message; reusing it with the same key reveals whether two messages start with the same blocks.

Sources:
- <https://csrc.nist.gov/pubs/ir/8459/final> — NIST IR 8459, report on the block cipher modes in the SP 800-38 series
- <https://csrc.nist.gov/pubs/sp/800/38/d/final> — NIST SP 800-38D, GCM, an authenticated mode used in practice

## 10. Reference list

1. H. Feistel, "Cryptography and Computer Privacy", *Scientific American* 228(5), 1973.
2. C. E. Shannon, "Communication Theory of Secrecy Systems", *Bell System Technical Journal* 28(4), 1949. <https://ieeexplore.ieee.org/document/6769090>
3. A. Menezes, P. van Oorschot, S. Vanstone, *Handbook of Applied Cryptography*, CRC Press, 1996, Chapter 7. <https://cacr.uwaterloo.ca/hac/about/chap7.pdf>
4. NIST, *FIPS 197: Advanced Encryption Standard (AES)*, 2001, updated 2023. <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf>
5. M. Dworkin, *NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation: Methods and Techniques*, 2001. <https://csrc.nist.gov/pubs/sp/800/38/a/final>
6. NIST IR 8459, *Report on the Block Cipher Modes of Operation in the NIST SP 800-38 Series*. <https://csrc.nist.gov/pubs/ir/8459/final>
7. R. Housley, *RFC 5652: Cryptographic Message Syntax (CMS)*, 2009, Section 6.3. <https://datatracker.ietf.org/doc/html/rfc5652#section-6.3>
8. S. Josefsson, *RFC 4648: The Base16, Base32, and Base64 Data Encodings*, 2006, Section 4. <https://datatracker.ietf.org/doc/html/rfc4648#section-4>
9. Python documentation, `os.urandom`. <https://docs.python.org/3/library/os.html#os.urandom>
10. Wikipedia: [Feistel cipher](https://en.wikipedia.org/wiki/Feistel_cipher), [Rijndael S-box](https://en.wikipedia.org/wiki/Rijndael_S-box), [Rijndael key schedule](https://en.wikipedia.org/wiki/Rijndael_key_schedule), [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation), [Padding (cryptography)](https://en.wikipedia.org/wiki/Padding_(cryptography)), [Padding oracle attack](https://en.wikipedia.org/wiki/Padding_oracle_attack), [Confusion and diffusion](https://en.wikipedia.org/wiki/Confusion_and_diffusion), [Base64](https://en.wikipedia.org/wiki/Base64)
