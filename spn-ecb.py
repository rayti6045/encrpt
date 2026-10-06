# Educational block cipher: 128-bit substitution-permutation network (SPN) with
# AES S-box, bit permutation and AES-128 key schedule, ECB mode, PKCS#7 padding,
# Base64 output. Algorithm descriptions: see README_SPN.md

import base64

# AES S-box: 256-entry substitution table (bijection on bytes).
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf - FIPS 197 Sec. 5.1.1: official AES S-box table
# https://en.wikipedia.org/wiki/Rijndael_S-box - how the S-box is constructed (GF(2^8) inverse + affine transform)
S_BOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# Inverse S-box (INV_S_BOX[S_BOX[x]] == x). An SPN needs every layer to be
# invertible so that decryption can undo the rounds.
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf - FIPS 197 Sec. 5.3.2: InvSubBytes, inverse S-box
INV_S_BOX = [0] * 256
for _i, _v in enumerate(S_BOX):
    INV_S_BOX[_v] = _i

# Round constants for the AES-128 key schedule.
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf - FIPS 197 Sec. 5.2: Rcon values
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

ROUNDS = 10
BLOCK_SIZE = 16

# Bit permutation layer: the 128-bit state is viewed as a 16 x 8 bit matrix
# (16 bytes, 8 bits each) and transposed, so the 8 bits of every byte are
# spread over 8 different bytes (diffusion). P_BOX[pos] = new position of the
# bit that is at position pos (bits numbered from the most significant bit).
# The exact permutation is an own design choice.
# https://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf - Heys, SPN tutorial Sec. 2.2: bit permutation layer of an SPN
P_BOX = [(pos % 8) * 16 + pos // 8 for pos in range(128)]


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def substitute(data):
    return bytes(S_BOX[x] for x in data)


def inv_substitute(data):
    return bytes(INV_S_BOX[x] for x in data)


def to_bits(data):
    return [(byte >> (7 - k)) & 1 for byte in data for k in range(8)]


def from_bits(bits):
    return bytes(
        sum(bit << (7 - k) for k, bit in enumerate(bits[i:i + 8]))
        for i in range(0, len(bits), 8)
    )


def permute(data):
    bits = to_bits(data)
    out = [0] * 128
    for pos in range(128):
        out[P_BOX[pos]] = bits[pos]
    return from_bits(out)


def inv_permute(data):
    bits = to_bits(data)
    return from_bits([bits[P_BOX[pos]] for pos in range(128)])


# Key schedule: the AES-128 key expansion, giving ROUNDS + 1 = 11 round keys of
# 16 bytes (RotWord, SubWord and XOR with Rcon every 4th word).
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf - FIPS 197 Sec. 5.2: AES key expansion
def generate_round_keys(key):
    words = [key[i:i + 4] for i in range(0, 16, 4)]
    for i in range(4, 4 * (ROUNDS + 1)):
        temp = words[i - 1]
        if i % 4 == 0:
            temp = substitute(temp[1:] + temp[:1])
            temp = xor_bytes(temp, bytes([RCON[i // 4 - 1], 0, 0, 0]))
        words.append(xor_bytes(words[i - 4], temp))
    return [b"".join(words[4 * r:4 * r + 4]) for r in range(ROUNDS + 1)]


# SPN on one block. Every round: XOR round key -> S-box layer -> bit permutation.
# The last round has no permutation and is followed by a final key XOR.
# https://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf - Heys, SPN tutorial Sec. 2: basic SPN (key mixing, S-boxes, permutation, last round without permutation)
# https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network - SPN structure (used by AES)
def encrypt_block(block, round_keys):
    state = block
    for r in range(ROUNDS):
        state = xor_bytes(state, round_keys[r])
        state = substitute(state)
        if r < ROUNDS - 1:
            state = permute(state)
    return xor_bytes(state, round_keys[ROUNDS])


# Decryption: every step of encryption undone in reverse order
# (final key XOR, then inverse permutation -> inverse S-box -> key XOR per round).
def decrypt_block(block, round_keys):
    state = xor_bytes(block, round_keys[ROUNDS])
    for r in reversed(range(ROUNDS)):
        if r < ROUNDS - 1:
            state = inv_permute(state)
        state = inv_substitute(state)
        state = xor_bytes(state, round_keys[r])
    return state


# PKCS#7 padding.
# https://datatracker.ietf.org/doc/html/rfc5652#section-6.3 - RFC 5652 Sec. 6.3: PKCS#7 padding rule
def pad(data):
    amount = 16 - len(data) % 16
    return data + bytes([amount]) * amount


def unpad(data):
    amount = data[-1]
    if amount < 1 or amount > 16:
        raise ValueError("Invalid padding")
    if data[-amount:] != bytes([amount]) * amount:
        raise ValueError("Invalid padding")
    return data[:-amount]


# ECB mode: every 16-byte block is encrypted independently with the same key.
# https://csrc.nist.gov/pubs/sp/800/38/a/final - NIST SP 800-38A Sec. 6.1: ECB mode definition
# https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB) - ECB explained
# Ciphertext is Base64-encoded for text output.
# https://datatracker.ietf.org/doc/html/rfc4648#section-4 - RFC 4648 Sec. 4: Base64
def encrypt_message(message, key):
    round_keys = generate_round_keys(key)
    message = pad(message)
    encrypted = bytearray()

    for i in range(0, len(message), 16):
        block = message[i:i + 16]
        block = encrypt_block(block, round_keys)
        encrypted.extend(block)

    return base64.b64encode(bytes(encrypted)).decode()


def decrypt_message(encoded_message, key):
    raw = base64.b64decode(encoded_message)
    round_keys = generate_round_keys(key)
    decrypted = bytearray()

    for i in range(0, len(raw), 16):
        block = raw[i:i + 16]
        decrypted_block = decrypt_block(block, round_keys)
        decrypted.extend(decrypted_block)

    return unpad(bytes(decrypted)).decode()


def get_key():
    while True:
        key = input("Enter a 16-character key: ").encode()
        if len(key) == 16:
            return key
        print("The key must contain exactly 16 ASCII characters.")


def main():
    while True:
        print("\n1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            key = get_key()
            message = input("Enter plaintext: ").encode()
            result = encrypt_message(message, key)
            print("\nEncrypted text:")
            print(result)

        elif choice == "2":
            key = get_key()
            encrypted = input("Enter encrypted text: ")
            try:
                result = decrypt_message(encrypted, key)
                print("\nDecrypted text:")
                print(result)
            except Exception:
                print("Decryption failed.")

        elif choice == "3":
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
