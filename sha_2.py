from utils import (
    split_blocks,
    rotr,
    add_hash_padding,
    flip_random_bit,
    string_to_bitstring
)
from math_utils import hamming_distance_bits


h32 = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
]


k32 = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
]


h64 = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
]


k64 = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
     0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
     0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
     0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
     0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
     0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
     0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
     0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
     0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
     0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
     0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
     0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
     0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
     0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
     0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
     0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]


class SHA2:

    _SHA256_PARAMS = {
        "initial_hash": h32,
        "round_constants": k32,
        "block_size": 64,
        "word_size": 32,
        "word_bytes": 4,
        "length_size": 8,
        "rounds": 64,
        "small_sigma0": (7, 18, 3),
        "small_sigma1": (17, 19, 10),
        "big_sigma0": (2, 13, 22),
        "big_sigma1": (6, 11, 25),
    }

    _SHA512_PARAMS = {
        "initial_hash": h64,
        "round_constants": k64,
        "block_size": 128,
        "word_size": 64,
        "word_bytes": 8,
        "length_size": 16,
        "rounds": 80,
        "small_sigma0": (1, 8, 7),
        "small_sigma1": (19, 61, 6),
        "big_sigma0": (28, 34, 39),
        "big_sigma1": (14, 18, 41),
    }


    def sha_256(self, data: bytes) -> bytes:
        return self._hash(data, self._SHA256_PARAMS)


    def sha_512(self, data: bytes) -> bytes:
        return self._hash(data, self._SHA512_PARAMS)


    def _hash(self, data:bytes, params: dict) -> bytes:
        word_size = params["word_size"]
        word_bytes = params["word_bytes"]
        block_size = params["block_size"]
        rounds = params["rounds"]
        mask = (1 << word_size) - 1

        h = params["initial_hash"].copy()
        k = params["round_constants"]

        padded = add_hash_padding(data, block_size=block_size)
        blocks = split_blocks(padded, block_size=block_size)

        for block in blocks:

            w = [
                int.from_bytes(splitting, "big")
                for splitting in split_blocks(block, block_size=word_bytes)
            ]
            w += [0] * (rounds - 16)

            for i in range(16, rounds):
                w[i] = (
                    w[i - 16] +
                    self._small_sigma(w[i - 15], params["small_sigma0"], word_size) +
                    w[i - 7] +
                    self._small_sigma(w[i - 2], params["small_sigma1"], word_size)
                ) & mask

            a, b, c, d, e, f, g, hh = h

            for i in range(rounds):
                temp1 = (
                    hh +
                    self._big_sigma(e, params["big_sigma1"], word_size) +
                    self.ch(e, f, g, mask=mask) +
                    k[i] +
                    w[i]
                ) & mask

                temp2 = (
                    self._big_sigma(a, params["big_sigma0"], word_size) +
                    self.maj(a, b, c)
                ) & mask

                hh,g,f = g,f,e
                e = (d + temp1) & mask
                d,c,b = c, b, a
                a = (temp1 + temp2) & mask

            working = (a, b, c, d, e, f, g, hh)
            h = [
                (old + new) & mask
                for old, new in zip(h, working)
            ]

        digest = b"".join(
            value.to_bytes(word_bytes, byteorder="big")
            for value in h
        )

        return digest


    @staticmethod
    def _small_sigma(x: int, params: tuple, word_size: int) -> int:
        r1, r2, shift = params
        return rotr(x, r1, word_size) ^ rotr(x, r2, word_size) ^ (x >> shift)


    @staticmethod
    def _big_sigma(x: int, params: tuple, word_size: int) -> int:
        r1, r2, r3 = params
        return rotr(x, r1, word_size) ^ rotr(x, r2, word_size) ^ rotr(x, r3, word_size)


    @staticmethod
    def ch(x: int, y: int, z: int, mask: int) -> int:
        return (x & y) ^ ((~x & mask) & z)


    @staticmethod
    def maj(x: int, y: int, z: int) -> int:
        return (x & y) ^ (x & z) ^ (y & z)


def avalanche_effect(
        sha: SHA2,
        text: str,
        algorithm: str = "sha_256"
) -> tuple[int, float, int]:

    if algorithm not in ("sha_256", "sha_512"):
        raise ValueError("Поддерживаются только sha_256 и sha_512")

    bits = string_to_bitstring(text)

    modified_bits = flip_random_bit(bits)

    original_bytes = bytes(
        int(bits[i:i + 8], 2)
        for i in range(0, len(bits), 8)
    )
    modified_bytes = bytes(
        int(modified_bits[i:i + 8], 2)
        for i in range(0, len(modified_bits), 8)
    )

    hash_func = getattr(sha, algorithm)

    hash1 = hash_func(original_bytes)
    hash2 = hash_func(modified_bytes)

    hash1_bits = "".join(f"{byte:08b}" for byte in hash1)
    hash2_bits = "".join(f"{byte:08b}" for byte in hash2)

    distance, percent = hamming_distance_bits(hash1_bits, hash2_bits)

    return distance, percent, len(hash1)