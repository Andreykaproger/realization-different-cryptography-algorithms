import secrets

from xtea import XTEA
from utils import (
    key_to_words,
    generate_key,
    key_to_bytes,
    int_to_block,
    encode_b64
)
from rsa import RSA
from sha_2 import SHA2, avalanche_effect
from digital_signature import RsaSignature


def main_xtea():
    def choose_key_xtea():
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

    key = choose_key_xtea()

    print(key_to_bytes(key).hex())

    cipher = XTEA(key)

    text = input("Введите текст, который хотите зашифровать:")

    encrypted = cipher.encrypt(text)

    print("Hex-код текста:",encrypted.hex())

    decrypted = cipher.decrypt(encrypted)

    print("Расшифрованный текст:", decrypted)


def main_rsa():
    rsa = RSA(bits=10)

    text = input("Введите текст, который хотите зашифровать:")

    rsa.generate_keypair()
    print(f"Сгенерированный открытый ключ: {rsa.public_key}")
    print(f"Сгенерированный закрытый ключ: {rsa.private_key}")

    encrypted = rsa.encrypt(text)
    print(f"Зашифрованный текст: {encrypted[0].decode('ascii')}")

    decrypted = rsa.decrypt(encrypted)
    print(f"Расшифрованный текст: {decrypted}")

    print(f"{text!r} -> {decrypted!r}: {text == decrypted}")


def main_sha2():
    def choose_key_sha2():
        print(
            "Выберите версию SHA-2:\n"
            "1. SHA-256\n"
            "2. SHA-512\n"
            "Выберете необходимый параметр:"
        )
        tries = 0
        while tries < 5:
            try:
                parameter = int(input())
                if parameter == 1:
                    version = "sha_256"
                elif parameter == 2:
                    version = "sha_512"
                else:
                    raise ValueError("Выберете вариант от 1 до 2:")

                return version

            except ValueError as e:
                tries += 1
                print(f"Ошибка: {e}")
                print(f"Попыток осталось: {5 - tries}")
                print("Выберете заново необходимый размер хэша:")

        raise ValueError("Некорректный выбор ключа")

    version = choose_key_sha2()

    text = input("Введите текст, который хотите хэшировать:")

    sha2 = SHA2()

    results = {
        "sha_256": sha2.sha_256(text.encode()),
        "sha_512": sha2.sha_512(text.encode())
    }

    text_hash = results[version]

    distance, percent, hash_len = avalanche_effect(sha2, text, algorithm=version)

    print(
        f"Исходный текст в формате hex: {text.encode().hex()}\n"
        f"Хэш исходного текста в формате hex: {text_hash.hex()}\n"
        "Оценка лавинного эффекта:\n"
        f"Изменено битов во входных данных: 1\n"
        f"Различается битов хэша: {distance} из {hash_len * 8}\n"
        f"Лавинный эффект: {percent:.2f}%"
    )


def main_ds():
    def choose_key_ds():
        print(
            "Выберите сценарий проверки подписи:\n"
            "1. Подписание и проверка оригинального сообщения.\n"
            "2. Изменение сообщения при сохранении исходной подписи.\n"
            "3. Попытка сформировать поддельную подпись без закрытого ключа.\n"
            "Выберете необходимый параметр:"
        )

        tries = 0
        while tries < 5:
            try:
                scenario = int(input())
                if scenario not in range(1, 4):
                    raise ValueError("Выберете вариант от 1 до 3:")

                return scenario

            except ValueError as e:
                tries += 1
                print(f"Ошибка: {e}")
                print(f"Попыток осталось: {5 - tries}")
                print("Выберете заново сценарий:")

        raise ValueError("Некорректный выбор ключа")


    def print_signature_details(sign):
        print(
            f"""
                SHA-256 дайджест текста: {sign.hash_hex}
                Hash в виде числа: {sign.int_message}
                Расчет подписи на основе RSA (S = H(M)^d mod n):
                {sign.int_sign}
                Подпись в формате Base64:
                {sign.b64_sign}
        """
        )

    def print_verify_details(verify, text, pk):
        print(
            f"""
            Полученное сообщение для проверки: {text}
            Открытый ключ отправителя:
            e = {pk[0]}
            n = {pk[1]} 

            Вычисленный хэш сообщения:
            H(M): {verify.hash_hex}
            H(M) в виде числа: {verify.int_message}

            Полученная подпись в виде числа:
            {verify.int_sign}
            Проверка RSA подписи:
            S^e mod n = H(M): {verify.sign_hash}

            Сравнение хэшей:
            Хеш сообщения: {verify.int_message}
            Хеш из подписи: {verify.sign_hash}

            Результат:
            {"Хеши совпадают\nЦифровая подпись действительна"
            if verify.is_valid else "Хеши не совпадают\nЦифровая подпись недействительна!"
            }
           """
        )

    text = input("Введите текст, который хотите подписать: ")

    rsa = RSA(bits=129)
    pk, sk = rsa.generate_keypair()
    rsa_sign = RsaSignature()
    sign = rsa_sign.sign_detailed(text, sk)
    print_signature_details(sign)

    scenario = choose_key_ds()

    if scenario == 1:

        verify = rsa_sign.verify_detailed(sign.b64_sign, text, pk)
        print_verify_details(verify, text, pk)

    elif scenario == 2:
        changes = input(f"Измените исходный текст: {text}")

        verify = rsa_sign.verify_detailed(sign.b64_sign, changes, pk)
        print_verify_details(verify, changes, pk)

    elif scenario == 3:

        fake_sign = int_to_block(secrets.randbelow(pk[1]), (pk[1].bit_length() + 7) // 8)
        b64_fake_sign = encode_b64(fake_sign)

        print(f"Cформирована поддельная цифровая подпись: {b64_fake_sign}")
        verify = rsa_sign.verify_detailed(b64_fake_sign, text, pk)
        print_verify_details(verify, text, pk)


def main():
    print(
        "Выберите режим:\n"
        "1. Шифрование XTEA\n"
        "2. Шифрование RSA\n"
        "3. Хеширование SHA-2\n"
        "4. Электронная цифровая подпись\n"
        "Выберете необходимый параметр:"
    )
    tries = 0
    while tries < 5:
        try:
            parameter = int(input())
            if parameter == 1:
                return main_xtea()
            elif parameter == 2:
                return main_rsa()
            elif parameter == 3:
                return main_sha2()
            elif parameter == 4:
                return main_ds()

            else:
                raise IndexError("Выберете вариант от 1 до 4:")


        except IndexError as e:
            tries += 1
            print(f"Ошибка: {e}")
            print(f"Попыток осталось: {5 - tries}")
            print("Выберете заново режим:")

    raise ValueError("Некорректный выбор ключа")


if __name__ == "__main__":
    main()