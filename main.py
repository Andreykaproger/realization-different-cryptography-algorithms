import struct

from xtea import XTEA
from utils import key_to_words, generate_key, key_to_bytes


def choose_key():
    print(
    "Выберите способ задания ключа:\n"
    "1. Сгенерировать ключ\n"
    "2. Ввести HEX-ключ\n"
    "3. Ввести текстовый ключ\n"
    "Выберете необходимый параметр:"
)
    tries = 0
    while tries < 5:
        try:
            parameter = int(input())
            if parameter == 1:
                key = generate_key()
            elif parameter == 2:
                key = read_hex_key()
            elif parameter == 3:
                key = read_text_key()
            else:
                raise ValueError("Выберете вариант от 1 до 3:")

            return key

        except ValueError as e:
            tries += 1
            print(f"Ошибка: {e}")
            print(f"Попыток осталось: {5-tries}")
            print("Выберете заново способ задания ключа:")

    raise ValueError("Некорректный выбор ключа")



def read_hex_key():
    user_hex_key = input("Введите HEX-ключ:")

    try:
        key_bytes = bytes.fromhex(user_hex_key)
    except ValueError:
        raise ValueError("Указан некорректный HEX-ключ")

    if len(key_bytes) != 16:
        raise ValueError("Указана неверная длина ключа")

    key = key_to_words(key_bytes)

    return key


def read_text_key():
    user_text_key = input("Введите текстовый ключ:")

    key_bytes = user_text_key.encode("utf-8")

    if len(key_bytes) != 16:
        raise ValueError("Указана неверная длина ключа")

    key = key_to_words(key_bytes)

    return key

print("Алгоритм шифрования XTEA")

key = choose_key()

print(key_to_bytes(key).hex())

cipher = XTEA(key)

text = input("Введите текст, который хотите зашифровать:")

encrypted = cipher.encrypt(text)

print("Hex-код текста:",encrypted.hex())

decrypted = cipher.decrypt(encrypted)

print("Расшифрованный текст:", decrypted)