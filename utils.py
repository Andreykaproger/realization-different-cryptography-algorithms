import struct
import secrets


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