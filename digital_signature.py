from rsa import RSA
from sha_2 import SHA2
from utils import block_to_int, int_to_block
from math_utils import power
from utils import encode_b64, decode_b64


class RsaSignature:

    def __init__(self, rsa: RSA, sha: SHA2):
        self.rsa = rsa
        self.sha = sha


    def sign(self, message: str, private_key) -> str:
        d,n = private_key

        message_hash = self.sha.sha_256(message.encode()) # return bytes
        int_message = block_to_int(message_hash)

        if not 0 <= int_message < n:
            raise ValueError("hash message value must be in range [0, n)")

        int_sign = power(int_message, d, n)
        bytes_sign = int_to_block(int_sign, (n.bit_length()+7) // 8)
        b64_sign = encode_b64(bytes_sign)

        return b64_sign


    def verify(self, b64_sign: str, message: str, public_key) -> bool:
        e, n = public_key

        sign = decode_b64(b64_sign)
        cipher_block_size = (n.bit_length() + 7 )// 8

        if len(sign) != cipher_block_size:
            raise ValueError("Invalid sign length")

        int_sign = block_to_int(sign)
        if not 0 <= int_sign < n:
            raise ValueError("Sign value must be in range [0, n)")

        sign_hash = power(int_sign, e, n)
        message_hash = self.sha.sha_256(message.encode())
        int_message = block_to_int(message_hash)

        return sign_hash == int_message


