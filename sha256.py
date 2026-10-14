# Educational implementation of the SHA-256 hash function (FIPS 180-4).
# Algorithm descriptions: see README_SHA256.md

# SHA-256 works on 32-bit words; all additions are done modulo 2^32.
MASK = 0xFFFFFFFF

# Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes.
# https://doi.org/10.6028/NIST.FIPS.180-4 - FIPS 180-4 Sec. 5.3.3: SHA-256 initial hash value
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes.
# https://doi.org/10.6028/NIST.FIPS.180-4 - FIPS 180-4 Sec. 4.2.2: SHA-256 constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


# Logical functions used by SHA-256: Ch, Maj, big sigma (S0, S1) and small sigma (s0, s1).
# https://doi.org/10.6028/NIST.FIPS.180-4 - FIPS 180-4 Sec. 4.1.2: SHA-256 functions
def ch(x, y, z):
    return (x & y) ^ (~x & z)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def big_sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def small_sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def small_sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


# Message padding: append a 1 bit (0x80), then zero bytes until the length is
# 56 mod 64, then the original message length in bits as a 64-bit big-endian number.
# https://doi.org/10.6028/NIST.FIPS.180-4 - FIPS 180-4 Sec. 5.1.1: padding the message (SHA-256)
def pad_message(message):
    length_bits = len(message) * 8
    message += b"\x80"
    message += b"\x00" * ((56 - len(message) % 64) % 64)
    message += length_bits.to_bytes(8, "big")
    return message


# Compression function: processes one 64-byte block and updates the 8 hash words.
# Step 1 builds the 64-word message schedule, step 2 runs 64 rounds, step 3 adds the result to the old hash value.
# https://doi.org/10.6028/NIST.FIPS.180-4 - FIPS 180-4 Sec. 6.2.2: SHA-256 hash computation
def process_block(block, h):
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        w.append((small_sigma1(w[t - 2]) + w[t - 7] + small_sigma0(w[t - 15]) + w[t - 16]) & MASK)

    a, b, c, d, e, f, g, hh = h
    for t in range(64):
        temp1 = (hh + big_sigma1(e) + ch(e, f, g) + K[t] + w[t]) & MASK
        temp2 = (big_sigma0(a) + maj(a, b, c)) & MASK
        hh = g
        g = f
        f = e
        e = (d + temp1) & MASK
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK

    return [(x + y) & MASK for x, y in zip(h, [a, b, c, d, e, f, g, hh])]


# The whole hash: pad the message, process it block by block (each block feeds
# its result into the next one), output the 8 words as 64 hex characters.
# https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction - iterated block-by-block hashing used by SHA-2
def sha256(message):
    message = pad_message(message)
    h = H0[:]
    for i in range(0, len(message), 64):
        h = process_block(message[i:i + 64], h)
    return "".join(f"{word:08x}" for word in h)


def main():
    while True:
        print("\n1. Hash text")
        print("2. Hash file")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            text = input("Enter text: ").encode()
            print("\nSHA-256:")
            print(sha256(text))

        elif choice == "2":
            path = input("Enter file path: ")
            try:
                with open(path, "rb") as file:
                    data = file.read()
            except OSError:
                print("Cannot read file.")
                continue
            print("\nSHA-256:")
            print(sha256(data))

        elif choice == "3":
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
