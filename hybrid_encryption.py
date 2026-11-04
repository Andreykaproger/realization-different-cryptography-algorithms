from xtea import XTEA
from utils import (
    encode_b64,
    decode_b64,
    block_to_int,
    int_to_block,
    key_to_bytes,
    bytes_to_key
)
from math_utils import power



class HybridEncryption:

    def encrypt_text(self, text: str, session_key: tuple) -> str:
        xtea = XTEA(session_key)
        encrypted_text = xtea.encrypt(text)

        return encode_b64(encrypted_text)


    def decrypt_text(self, data: str, session_key: tuple) -> str:
        xtea = XTEA(session_key)

        text = decode_b64(data)

        decrypted_text = xtea.decrypt(text)

        return decrypted_text


    def encrypt_key(self, public_key: tuple[int,int], session_key: tuple) -> str:
        e, n = public_key
        bytes_key = key_to_bytes(session_key)

        if len(bytes_key) != XTEA.KEY_SIZE:
            raise ValueError("Некорректная длина сеансового ключа")

        value = block_to_int(bytes_key)
        if not 0 <= value < n:
            raise ValueError("Значение ключа должно быть в диапазоне [0, n)")

        encrypted_key = power(value, e, n)

        bytes_rsa_key = int_to_block(encrypted_key, (n.bit_length() + 7) // 8)

        return encode_b64(bytes_rsa_key)


    def decrypt_key(self, key: str, private_key: tuple[int, int]) -> tuple:
        d,n = private_key
        bytes_encoded_key = decode_b64(key)

        if len(bytes_encoded_key) != (n.bit_length() + 7 )// 8:
            raise ValueError("Некорректная длина ключа")

        int_key = block_to_int(bytes_encoded_key)

        if not 0 <= int_key < n:
            raise ValueError("Значение ключа должно быть в диапазоне от [0, n)")

        decrypted_key = power(int_key, d, n)
        bytes_key = int_to_block(decrypted_key, XTEA.KEY_SIZE)

        if len(bytes_key) != XTEA.KEY_SIZE:
            raise ValueError("Некорректный восстановленный ключ")

        session_key = bytes_to_key(bytes_key)

        return session_key


    def encrypt_bytes(self, data: bytes, session_key: tuple) -> str:
        return self.encrypt_text(data.decode(), session_key)


    def decrypt_bytes(self, data: str, session_key: tuple) -> bytes:
        return self.decrypt_text(
            data, session_key
        ).encode()


# from rsa import RSA
#
# rsa = RSA(bits=65)
# pk, sk = rsa.generate_keypair()
#
# alice = HybridEncryption()
# session_key = generate_key()
# enc_text = alice.encrypt_text(text="HEEEEEELLLLO", session_key=session_key)
# enc_key = alice.encrypt_key(pk, session_key=session_key)
# print(f"""
#     Сгенерированная пара ключей:
#     public: {pk}, private: {sk}
#
#     Зашифрованный текст симметричным шифрованием:
#     {enc_text}
#
#     Зашифрованный симметричный ключ ассиметричным открытым ключом:
#     {enc_key}
#
# """)
# print("====================================================")
# bob = HybridEncryption()
# dec_key = bob.decrypt_key(enc_key, sk)
# dec_text = bob.decrypt_text(enc_text, dec_key)
#
# print(f"""
#     Дешифрованный симметричный ключ ассиметричным закрытым ключом:
#     {dec_key}
#
#     Дешифрованный текст симметричным ключом:
#     {dec_text}
#
# """)