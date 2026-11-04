from sha_2 import SHA2
from utils import block_to_int, int_to_block
from math_utils import power
from utils import encode_b64, decode_b64
from models import VerifyCheck, SignatureResult


class RsaSignature:

    def __init__(self):
        self.sha = SHA2()


    def sign(self, message: str, private_key: tuple[int,int]) -> str:
        return self.sign_detailed(message, private_key).b64_sign


    def verify(self, b64_sign: str, message: str, public_key: tuple[int,int]) -> bool:
        return self.verify_detailed(b64_sign, message, public_key).is_valid


    def verify_detailed(self, b64_sign: str, message: str, public_key: tuple[int,int]) -> VerifyCheck:
        e, n = public_key

        sign = decode_b64(b64_sign)
        cipher_block_size = (n.bit_length() + 7 )// 8

        if len(sign) != cipher_block_size:
            raise ValueError("Некорректная длина подписи")

        int_sign = block_to_int(sign)
        if not 0 <= int_sign < n:
            raise ValueError("Значение подписи должно быть в диапазоне от [0, n)")

        sign_hash = power(int_sign, e, n)
        message_hash = self.sha.sha_256(message.encode())
        int_message = block_to_int(message_hash)
        is_valid = sign_hash == int_message

        return VerifyCheck(
            message_hash = message_hash,
            hash_hex = message_hash.hex(),
            int_message = int_message,
            int_sign= int_sign,
            sign_hash = sign_hash,
            is_valid=is_valid
        )


    def sign_detailed(self, message: str, private_key: tuple[int, int]) -> SignatureResult:
        d,n = private_key

        message_hash = self.sha.sha_256(data=message.encode()) # return bytes
        int_message = block_to_int(message_hash)

        if not 0 <= int_message < n:
            raise ValueError("hash message value must be in range [0, n)")

        int_sign = power(int_message, d, n)
        bytes_sign = int_to_block(int_sign, (n.bit_length()+7) // 8)
        b64_sign = encode_b64(bytes_sign)

        return SignatureResult(
            message_hash=message_hash,
            hash_hex=message_hash.hex(),
            int_message=int_message,
            int_sign=int_sign,
            b64_sign=b64_sign
        )