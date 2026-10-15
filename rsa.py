import base64
import secrets
import math

from miller_rabin_test import miller_rabin
from utils import (
    split_blocks,
    block_to_int,
    int_to_block,
    get_block_size,
)
from math_utils import miller_rabin, power, modinv


class RSA:
    e = 65537

    def __init__(self, bits: int = 10):
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
            self.encrypt_block(block, n)
            for block in blocks
        ]

        b64_cipher = self.ciphertext_to_b64(encrypted_blocks)

        return b64_cipher, original_length


    def decrypt(self,encrypted_data: tuple[str, int]) -> str:
        d,n = self.private_key
        b64_text, original_length = encrypted_data

        encrypted_blocks = self.b64_to_ciphertext(b64_text)

        if not encrypted_blocks:
            return ""

        block_size = get_block_size(n)

        decrypted_blocks = []
        for block in encrypted_blocks[:-1]:
            decrypted_blocks.append(
                int_to_block(self.decrypt_block(block, d, n),block_size)
            )

        decrypted_blocks.append(
            int_to_block(self.decrypt_block(
                encrypted_blocks[-1], d, n), original_length % block_size or block_size)
        )

        decrypted_data = b"".join(decrypted_blocks)

        return decrypted_data.decode("utf-8")


    def ciphertext_to_b64(self, blocks: list[int]) -> base64:
        text = []
        _, n = self.public_key

        for block in blocks:
            text.append(
                int_to_block(block, (n.bit_length() + 7) // 8)
            )

        decrypted_data = b"".join(text)

        return base64.b64encode(decrypted_data)


    def b64_to_ciphertext(self, ciphertext_b64: str) -> list[str]:
        ciphertext_bytes = base64.b64decode(ciphertext_b64, validate=True)
        _, n = self.public_key

        cipher_block_size = (n.bit_length() + 7 )// 8

        if len(ciphertext_bytes) % cipher_block_size != 0:
            raise ValueError("Invalid ciphertext length")

        return [
            block_to_int(
                ciphertext_bytes[i:i+cipher_block_size]
            )
            for i in range(0, len(ciphertext_bytes), cipher_block_size)
        ]


    def encrypt_block(self, block: bytes, n: int) -> int:
        value = block_to_int(block)
        if not 0 <= value < n:
            raise ValueError("Block value must be in range [0, n)")
        return power(value, self.e, n)


    def decrypt_block(self, block: int, d: int, n: int) -> int:
        value = power(block, d, n)
        return value
