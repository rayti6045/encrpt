# SHA-256 Hash Function — Algorithm Description

This document explains the **algorithm** that `sha256.py` implements — not the Python code itself. Every section lists its sources; the same sources are referenced in the code comments.

> **Educational implementation.** The output was checked against Python's `hashlib` for many inputs, including all the padding boundary lengths, but real programs should use a vetted library.

## 1. Overview

A hash function turns a message of any length into a short fixed-size value (the **digest**). SHA-256 is part of the SHA-2 family standardised by NIST in FIPS 180-4; its digest is **256 bits** (64 hexadecimal characters).

| Stage | What happens |
|---|---|
| 1 | **Padding** — the message is extended so that its length is a multiple of 512 bits |
| 2 | **Parsing** — the padded message is cut into 512-bit (64-byte) blocks |
| 3 | **Initial hash value** — eight fixed 32-bit words are the starting state |
| 4 | **Compression** — every block updates the state: a 64-word *message schedule* is built, then 64 *rounds* of bit operations mix it in |
| 5 | **Output** — the final eight 32-bit words are concatenated into the 256-bit digest |

```
message ─► padding ─► 512-bit blocks M_1 … M_n
                          │
   H_0 (fixed) ─► [compress M_1] ─► H_1 ─► [compress M_2] ─► H_2 ─► … ─► H_n = digest
```

Sources:
- <https://doi.org/10.6028/NIST.FIPS.180-4> — NIST FIPS 180-4, Secure Hash Standard: the official specification
- <https://en.wikipedia.org/wiki/SHA-2> — overview of the SHA-2 family and SHA-256 pseudocode

## 2. Cryptographic hash functions in general

A **cryptographic hash function** `H` maps data of any size to a fixed-size digest and is designed to have these properties:

- **Deterministic:** the same input always gives the same digest.
- **Fast to compute** for any input.
- **Preimage resistance:** given a digest `d`, it is infeasible to find any message `m` with `H(m) = d` (one-way).
- **Second-preimage resistance:** given `m`, it is infeasible to find a different `m'` with `H(m') = H(m)`.
- **Collision resistance:** it is infeasible to find any two different messages with the same digest.
- **Avalanche effect:** changing one input bit changes about half of the digest bits. For example, `hello world` and `hello worle` (one character different) give digests that differ in 140 of 256 bits.

A hash is **not encryption**: there is no key and no way to recover the message from the digest. Typical uses are file integrity checks, digital signatures, and building other constructions such as HMAC.

| | Block cipher (ECB/CBC/SPN/Feistel) | Hash function (SHA-256) |
|---|---|---|
| Key | yes | no |
| Reversible | yes, with the key | no (one-way) |
| Output size | same as input | always 256 bits |
| Goal | confidentiality | integrity / fingerprint |

Sources:
- <https://en.wikipedia.org/wiki/Cryptographic_hash_function> — properties and uses of cryptographic hash functions
- <https://en.wikipedia.org/wiki/Avalanche_effect> — avalanche effect

## 3. Merkle–Damgård construction

SHA-256 is built with the **Merkle–Damgård construction**, which turns a **compression function** `f` (a function that takes a fixed-size state and a fixed-size block and returns a new state) into a hash function for messages of any length:

```
H_0 = fixed initial value
H_i = f( H_(i-1), M_i )        for every block M_i
digest = H_n
```

The message is first padded in a way that **includes its length**, which prevents trivial collisions between messages of different lengths. If the compression function is collision resistant, then so is the whole hash. In SHA-256 the compression function is a block-cipher-like sequence of 64 rounds, with the final addition of the old state ("feed-forward") making it one-way.

Sources:
- <https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction> — the construction, length padding, chaining
- R. C. Merkle, "A Certified Digital Signature", CRYPTO 1989; I. B. Damgård, "A Design Principle for Hash Functions", CRYPTO 1989 — the original papers

## 4. Words and operations

SHA-256 works on **32-bit words**, interpreted as **big-endian** numbers when read from bytes. All additions are **modulo 2³²**. The operations used are:

| Operation | Meaning |
|---|---|
| `x ⊕ y` | bitwise XOR |
| `x ∧ y` | bitwise AND |
| `¬x` | bitwise NOT |
| `ROTR_n(x)` | rotate the 32-bit word `x` right by `n` bits |
| `SHR_n(x)` | shift `x` right by `n` bits (zeros come in on the left) |
| `x + y` | addition modulo 2³² |

Six logical functions are built from them:

```
Ch(x,y,z)   = (x ∧ y) ⊕ (¬x ∧ z)           "choose": bits of y where x is 1, bits of z where x is 0
Maj(x,y,z)  = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)  "majority": the bit value that appears at least twice
Σ0(x) = ROTR_2(x)  ⊕ ROTR_13(x) ⊕ ROTR_22(x)
Σ1(x) = ROTR_6(x)  ⊕ ROTR_11(x) ⊕ ROTR_25(x)
σ0(x) = ROTR_7(x)  ⊕ ROTR_18(x) ⊕ SHR_3(x)
σ1(x) = ROTR_17(x) ⊕ ROTR_19(x) ⊕ SHR_10(x)
```

`Ch` and `Maj` are non-linear and provide confusion; the rotations in `Σ` and `σ` spread every input bit over many positions and provide diffusion — the same two principles as in the SPN cipher.

Source:
- <https://doi.org/10.6028/NIST.FIPS.180-4> — FIPS 180-4, Section 3.2 (operations) and Section 4.1.2 (SHA-256 functions)

## 5. Padding

The message length must become a multiple of 512 bits (64 bytes). For a message of `l` bits the padding is:

1. append one **`1` bit** (the byte `0x80`),
2. append **`0` bits** until the length is 448 mod 512 (56 mod 64 bytes),
3. append `l` as a **64-bit big-endian number**.

Example for the message `abc` (`l = 24 = 0x18`) — exactly one 64-byte block:

```
61 62 63 | 80 | 00 … 00  (52 zero bytes) | 00 00 00 00 00 00 00 18
 "abc"    1-bit      zero padding              length in bits
```

Padding is always applied, even if the message already fills a block (then a whole extra block is added), and the stored length makes the padding unambiguous. This is the hash counterpart of the PKCS#7 block-cipher padding, but it adds the message length instead of a repeated byte.

Source:
- <https://doi.org/10.6028/NIST.FIPS.180-4> — FIPS 180-4, Section 5.1.1: padding the message (SHA-256)

## 6. Constants

SHA-256 uses fixed constants, chosen in a transparent way so nobody can suspect a hidden weakness ("nothing-up-my-sleeve numbers"):

- **Initial hash value** `H_0` (8 words): the first 32 bits of the fractional parts of the **square roots** of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19). The first word is `0x6a09e667`.
- **Round constants** `K_0 … K_63` (64 words): the first 32 bits of the fractional parts of the **cube roots** of the first 64 primes. `K_0 = 0x428a2f98`, `K_63 = 0xc67178f2`.

The program uses the numeric values from the standard; recomputing them from the roots gives the same numbers.

Sources:
- <https://doi.org/10.6028/NIST.FIPS.180-4> — FIPS 180-4, Section 4.2.2 (constants) and Section 5.3.3 (initial hash value)
- <https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number> — why such constants are used

## 7. Compression function

For every 512-bit block `M` the current hash value `H = (H_0 … H_7)` is updated in three steps.

### Step 1: message schedule

The block is read as 16 big-endian words `W_0 … W_15`, and expanded to 64 words:

```
W_t = σ1(W_(t-2)) + W_(t-7) + σ0(W_(t-15)) + W_(t-16)        for t = 16 … 63
```

### Step 2: 64 rounds

Eight working variables start with the current hash value: `(a, b, c, d, e, f, g, h) = (H_0 … H_7)`. Then, for `t = 0 … 63`:

```
T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t
T2 = Σ0(a) + Maj(a,b,c)

h = g
g = f
f = e
e = d + T1
d = c
c = b
b = a
a = T1 + T2
```

```
 a  b  c  d  e  f  g  h          one round: the words shift down one place;
 │  │  │  │  │  │  │  │          a and e get new values computed from T1 and T2
 └──T2──┘  └─T1─┘ ...
```

Only `a` and `e` receive new values; the other six words just move one position, so every word is eventually mixed into the two "active" ones.

### Step 3: feed-forward

The working variables are added (modulo 2³²) to the hash value from before the block:

```
H_0 = a + H_0,  H_1 = b + H_1,  …,  H_7 = h + H_7
```

This addition makes the compression function one-way: without it, the 64 rounds could be run backwards.

Sources:
- <https://doi.org/10.6028/NIST.FIPS.180-4> — FIPS 180-4, Section 6.2.2: SHA-256 hash computation (message schedule, rounds, feed-forward)
- <https://en.wikipedia.org/wiki/SHA-2#Pseudocode> — the same algorithm as pseudocode

## 8. Output

After the last block, the eight words `H_0 … H_7` are written one after another as 8 hexadecimal digits each, giving the 256-bit digest (64 hex characters). Examples:

```
SHA-256("")    = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

The program prints exactly these values.

Source:
- <https://doi.org/10.6028/NIST.FIPS.180-4> — FIPS 180-4, Section 6.2 and Appendix B (SHA-256 examples)

## 9. Parameters

| Parameter | SHA-256 |
|---|---|
| Message size limit | less than 2⁶⁴ bits |
| Block size | 512 bits (64 bytes) |
| Word size | 32 bits |
| State (hash value) | 8 words = 256 bits |
| Message schedule | 64 words |
| Rounds per block | 64 |
| Digest size | 256 bits (64 hex characters) |

## 10. Security notes

- SHA-256 is a current standard and no practical attacks on it are known. The older **MD5** and **SHA-1** are broken for collision resistance and should not be used for security purposes.
- Because of the Merkle–Damgård structure, `H(m)` lets an attacker compute `H(m ‖ padding ‖ extra)` without knowing `m` (**length extension**). To authenticate messages with a secret key, use **HMAC** rather than `H(key ‖ message)`.
- SHA-256 is very **fast**, which is the opposite of what is wanted for storing passwords; use a deliberately slow password-hashing function (such as Argon2, scrypt or bcrypt) for that.

Sources:
- <https://en.wikipedia.org/wiki/Length_extension_attack> — length extension attacks on Merkle–Damgård hashes
- <https://datatracker.ietf.org/doc/html/rfc2104> — RFC 2104: HMAC
- <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html> — OWASP Password Storage Cheat Sheet

## 11. Reference list

1. NIST, *FIPS PUB 180-4: Secure Hash Standard (SHS)*, 2015. <https://doi.org/10.6028/NIST.FIPS.180-4>
2. R. C. Merkle, "A Certified Digital Signature", *CRYPTO 1989*.
3. I. B. Damgård, "A Design Principle for Hash Functions", *CRYPTO 1989*.
4. H. Krawczyk, M. Bellare, R. Canetti, *RFC 2104: HMAC: Keyed-Hashing for Message Authentication*, 1997. <https://datatracker.ietf.org/doc/html/rfc2104>
5. OWASP, *Password Storage Cheat Sheet*. <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
6. Wikipedia: [SHA-2](https://en.wikipedia.org/wiki/SHA-2), [Cryptographic hash function](https://en.wikipedia.org/wiki/Cryptographic_hash_function), [Merkle–Damgård construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction), [Avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect), [Nothing-up-my-sleeve number](https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number), [Length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack)
