import base64
import struct
import random
import secrets


def rotr(x:int, n:int, word_size: int) -> int:
    mask = (1 << word_size) - 1
    n %= word_size
    return ((x >> n) | (x << (word_size-n))) & mask


def add_hash_padding(message: bytes, block_size: int) -> bytes:
    message_bit_length = len(message) * 8

    padded = message + b"\x80"
    zeros = (block_size - block_size // 8 - len(padded)) % block_size
    padded += b"\x00" * zeros
    padded += message_bit_length.to_bytes(block_size // 8, byteorder="big")
    return padded


def get_block_size(n: int) -> int:
    return (n.bit_length() - 1) // 8


def key_to_words(key):
    return struct.unpack(">4I", key)


def key_to_bytes(key):
    return struct.pack(">4I", *key)


def generate_key():
    key = secrets.token_bytes(16)

    return struct.unpack(">4I", key)


def block_to_words(block):
    return struct.unpack(">2I", block)


def words_to_block(v0,v1):
    return struct.pack(">2I",v0,v1)


def add_padding(block, block_size = 8):
    padding = block_size - len(block) % block_size
    block += bytes([padding])*padding

    return block


def split_blocks(data:bytes, block_size = 8):
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i+block_size])

    return blocks


def block_to_int(block):
    return int.from_bytes(block, byteorder="big")


def int_to_block(value: int, block_size: int) -> bytes:
    return value.to_bytes(block_size, byteorder="big")


def remove_padding(data:bytes, block_size = 8):
    if not data:
        raise ValueError("No data!")

    padding = data[-1]

    if not 1 <= padding <= block_size:
        raise ValueError("Invalid padding length")

    padding_in_data = data[-padding:]

    if padding_in_data != bytes([padding])*padding:
        raise ValueError("Padding is incorrect")

    return data[:-padding]


def string_to_bitstring(s: str, encoding: str = "utf-8") -> str:
    return "".join(format(byte, "08b") for byte in s.encode(encoding))


def flip_random_bit(bitstring: str, ) -> str:

    rng = random.Random()
    i = rng.randrange(len(bitstring))
    flipped = "1" if bitstring[i] == "0" else "0"
    return bitstring[:i] + flipped + bitstring[i + 1:]


def encode_b64(text: bytes):
    return base64.b64encode(text).decode("ascii")


def decode_b64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def blocks_to_b64(blocks: list[int], bit_size: int) -> str:
    text = []

    for block in blocks:
        text.append(
            int_to_block(block, (bit_size + 7) // 8)
        )

    data_bytes = b"".join(text)

    return encode_b64(data_bytes)


def b64_to_blocks(text: str, bit_size: int) -> list[int]:
    ciphertext_bytes = decode_b64(text)

    cipher_block_size = (bit_size + 7 )// 8

    if len(ciphertext_bytes) % cipher_block_size != 0:
        raise ValueError("Invalid ciphertext length")

    return [
        block_to_int(
            ciphertext_bytes[i:i+cipher_block_size]
        )
        for i in range(0, len(ciphertext_bytes), cipher_block_size)
    ]
