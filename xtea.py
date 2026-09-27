from utils import (
    add_padding,
    remove_padding,
    split_blocks,
    words_to_block,
    block_to_words
)


class XTEA:
    MASK = 0xFFFFFFFF
    DELTA = 0x9E3779B9
    ROUNDS = 32

    def __init__(self, key):
        self.key = self.__validate_key(key)


    def __validate_key(self, key: tuple) -> tuple[int]:
        if not isinstance(key, tuple):
            raise TypeError("Неверный формат ключа")
        if len(key) != 4:
            raise ValueError("Неверная длина ключа")

        for i in key:
            if not(type(i) is int and 0 <= i <= 0xFFFFFFFF):
                raise ValueError("Ошибка валидации ключа")

        return key

    def encrypt(self, text: str) -> bytes:
        bytes_text = text.encode()
        padding_text = add_padding(bytes_text)
        blocks = split_blocks(padding_text)
        result = b""
        for block in blocks:
            enblock = self._encrypt_block_bytes(block)
            result += enblock

        return result


    def decrypt(self, ciphertext: bytes):
        blocks = split_blocks(ciphertext)

        decrypted_text = b""
        for block in blocks:
            dec_block = self._decrypt_block_bytes(block)
            decrypted_text += dec_block

        text_without_padding = remove_padding(decrypted_text)

        return text_without_padding.decode()


    def _encrypt_block_bytes(self, block):
        v0, v1 = block_to_words(block)
        ev0, ev1 = self._encrypt_block(v0, v1, self.key)

        return words_to_block(ev0, ev1)


    def _decrypt_block_bytes(self, block):
        ev0, ev1 = block_to_words(block)
        v0, v1 = self._decrypt_block(ev0, ev1)

        return words_to_block(v0, v1)


    def _encrypt_block(self,v0, v1, key):
        summ = 0

        for _ in range(self.ROUNDS):
            v0 = (v0 + ((v1 + ((v1 << 4) ^ (v1 >> 5))) ^ (summ + key[summ & 3]))) & self.MASK
            summ = (summ + self.DELTA) & self.MASK
            v1 = (v1 + ((v0 + ((v0 << 4) ^ (v0 >> 5))) ^ (summ + key[(summ >> 11) & 3]))) & self.MASK

        return v0, v1


    def _decrypt_block(self, v0, v1):
        summ = (self.ROUNDS * self.DELTA) & self.MASK

        for _ in range(self.ROUNDS):
            v1 = (v1 - ((v0 + ((v0 << 4) ^ (v0 >> 5))) ^ (summ + self.key[(summ >> 11) & 3]))) & self.MASK
            summ = (summ - self.DELTA) & self.MASK
            v0 = (v0 - ((v1 + ((v1 << 4) ^ (v1 >> 5))) ^ (summ + self.key[summ & 3]))) & self.MASK

        return v0, v1