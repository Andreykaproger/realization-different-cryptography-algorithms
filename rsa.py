import secrets
import math

from math_utils import miller_rabin, power, modinv
from utils import (
    split_blocks,
    block_to_int,
    int_to_block,
    get_block_size,
    b64_to_blocks,
    blocks_to_b64
)


class RSA:
    e = 65537

    def __init__(self, bits: int = 129):
        self.bits = bits
        self.public_key: tuple[int, int] | None = None
        self.private_key: tuple[int, int] | None = None


    def generate_keypair(self):

        while True:
            p = self.generate_prime()
            q = self.generate_prime()

            if p == q:
                continue

            n = p * q
            phi = (p - 1) * (q - 1)

            if math.gcd(self.e, phi) != 1:
                continue

            d = modinv(self.e, phi)

            self.public_key = (self.e, n)
            self.private_key = (d, n)

            return self.public_key, self.private_key


    def generate_prime(self) -> int:
        while True:
            candidate = secrets.randbits(self.bits)
            candidate |= (1 << (self.bits - 1)) | 1

            if miller_rabin(candidate):
                return candidate


    def encrypt(self, text: str) -> tuple[str, int]:
        _, n = self.public_key
        value = text.encode("utf-8")
        original_length = len(value)
        block_size = get_block_size(n)

        if block_size < 1:
            raise ValueError("RSA modulus is too small for byte blocks")

        blocks = split_blocks(value, block_size)
        encrypted_blocks = [
            self._encrypt_block(block, n)
            for block in blocks
        ]

        b64_cipher = blocks_to_b64(encrypted_blocks, n.bit_length())

        return b64_cipher, original_length


    def decrypt(self,encrypted_data: tuple[str, int]) -> str:
        d,n = self.private_key
        b64_text, original_length = encrypted_data

        encrypted_blocks = b64_to_blocks(b64_text, n.bit_length())

        if not encrypted_blocks:
            return ""

        block_size = get_block_size(n)

        decrypted_blocks = []
        for block in encrypted_blocks[:-1]:
            decrypted_blocks.append(
                int_to_block(self._decrypt_block(block, d, n),block_size)
            )

        decrypted_blocks.append(
            int_to_block(self._decrypt_block(
                encrypted_blocks[-1], d, n), original_length % block_size or block_size)
        )

        decrypted_data = b"".join(decrypted_blocks)

        return decrypted_data.decode("utf-8")


    def _encrypt_block(self, block: bytes, n: int) -> int:
        value = block_to_int(block)
        if not 0 <= value < n:
            raise ValueError("Block value must be in range [0, n)")
        return power(value, self.e, n)


    def _decrypt_block(self, block: int, d: int, n: int) -> int:
        value = power(block, d, n)
        return value