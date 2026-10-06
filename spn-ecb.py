import base64

BLOCK_SIZE = 16  # bytes = 128 bits
ROUNDS = 10

# AES S-box (real one), maps one byte to another byte
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf - FIPS 197 (AES standard), section 5.1.1, the S-box table
# https://en.wikipedia.org/wiki/Rijndael_S-box - overview of how the AES S-box is built
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i


def make_round_keys(key):
    """Round key r = the key rotated left by r bytes, then XORed with r. Our own simple schedule."""
    round_keys = []
    for r in range(ROUNDS + 1):  # one extra key for the final XOR
        rotated = key[r % 16:] + key[:r % 16]
        round_keys.append(bytes(b ^ r for b in rotated))
    return round_keys


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def substitute(block, box):
    return bytes(box[b] for b in block)


# Bit permutation: bit i of the block moves to position (7 * i) mod 128.
# 7 has an inverse mod 128 (7 * 55 = 385 = 3 * 128 + 1), so the permutation can be undone.
# https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network - SPN structure, why a permutation layer follows the S-boxes
def permute_bits(block, multiplier):
    value = int.from_bytes(block, "big")
    result = 0
    for i in range(128):
        if (value >> i) & 1:
            result |= 1 << ((i * multiplier) % 128)
    return result.to_bytes(BLOCK_SIZE, "big")


def encrypt_block(block, round_keys):
    # each round: XOR with round key -> S-box -> bit permutation, then a final XOR
    for r in range(ROUNDS):
        block = xor_bytes(block, round_keys[r])
        block = substitute(block, SBOX)
        block = permute_bits(block, 7)
    return xor_bytes(block, round_keys[ROUNDS])


def decrypt_block(block, round_keys):
    # same steps backwards, each one undone
    block = xor_bytes(block, round_keys[ROUNDS])
    for r in reversed(range(ROUNDS)):
        block = permute_bits(block, 55)  # 55 = inverse of 7 mod 128
        block = substitute(block, INV_SBOX)
        block = xor_bytes(block, round_keys[r])
    return block


# https://datatracker.ietf.org/doc/html/rfc5652#section-6.3 - PKCS#7 padding: add N bytes of value N to fill the block
def pad(data):
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n


def unpad(data):
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding (wrong key or corrupted data)")
    return data[:-n]


def encrypt_message(text, key):
    round_keys = make_round_keys(key)
    data = pad(text.encode("utf-8"))
    # https://csrc.nist.gov/pubs/sp/800/38/a/final - NIST SP 800-38A, section 6.1: ECB mode, every block is encrypted independently
    blocks = [encrypt_block(data[i:i + BLOCK_SIZE], round_keys) for i in range(0, len(data), BLOCK_SIZE)]
    # https://datatracker.ietf.org/doc/html/rfc4648 - RFC 4648: Base64 encoding, to print binary ciphertext as text
    return base64.b64encode(b"".join(blocks)).decode()


def decrypt_message(text, key):
    round_keys = make_round_keys(key)
    data = base64.b64decode(text)
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a multiple of 16 bytes")
    blocks = [decrypt_block(data[i:i + BLOCK_SIZE], round_keys) for i in range(0, len(data), BLOCK_SIZE)]
    return unpad(b"".join(blocks)).decode("utf-8")


def get_key():
    while True:
        key = input("Key (exactly 16 characters = 128 bits): ").encode("utf-8")
        if len(key) == BLOCK_SIZE:
            return key
        print(f"Key is {len(key) * 8} bits, need exactly 128 bits (16 bytes). Try again.")


def main():
    while True:
        print("\n1) Encrypt  2) Decrypt  3) Exit")
        choice = input("Choose: ").strip()
        if choice == "3":
            break
        if choice not in ("1", "2"):
            print("Please type 1, 2 or 3.")
            continue
        key = get_key()
        try:
            if choice == "1":
                print("Ciphertext (Base64):", encrypt_message(input("Message: "), key))
            else:
                print("Plaintext:", decrypt_message(input("Ciphertext (Base64): ").strip(), key))
        except Exception as e:
            print("Error:", e)


if __name__ == "__main__":
    main()
