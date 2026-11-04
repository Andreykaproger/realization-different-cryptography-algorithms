from utils import generate_key
from digital_signature import RsaSignature
from hybrid_encryption import HybridEncryption
from message_serializer import serialize_signed_message, deserialize_signed_message

from models import (
    SignedMessage,
    EncryptedPackage,
    EncryptionResult,
    DecryptionResult,
)


class HybridProtocol:

    def __init__(self):
        self.rsa_signature = RsaSignature()
        self.hybrid_encryption = HybridEncryption()

    def encrypt(
        self,
        message: str,
        sender_private_key: tuple[int, int],
        recipient_public_key: tuple[int, int],
    ) -> EncryptionResult:

        # 1. Формируем цифровую подпись
        signature_result = self.rsa_signature.sign_detailed(
            message,
            sender_private_key
        )

        signed_message = SignedMessage(
            message=message,
            signature=signature_result.b64_sign
        )

        # 2. Сериализуем сообщение и подпись
        serialized_data = serialize_signed_message(signed_message)

        # 3. Генерируем сессионный ключ
        session_key = generate_key()

        # 4. Шифруем данные с помощью XTEA
        encrypted_data = self.hybrid_encryption.encrypt_bytes(
            serialized_data,
            session_key
        )

        # 5. Шифруем сессионный ключ открытым ключом получателя
        encrypted_session_key = self.hybrid_encryption.encrypt_key(
            recipient_public_key,
            session_key
        )

        # 6. Формируем пакет для отправки
        package = EncryptedPackage(
            encrypted_data=encrypted_data,
            encrypted_session_key=encrypted_session_key
        )

        return EncryptionResult(
            package=package,
            signature_result=signature_result,
            signed_message_json=serialized_data,
            session_key=session_key
        )

    def decrypt(
        self,
        encrypted_package: EncryptedPackage,
        recipient_private_key: tuple[int, int],
        sender_public_key: tuple[int, int],
    ) -> DecryptionResult:

        # 1. Расшифровываем сессионный ключ
        decrypted_session_key = self.hybrid_encryption.decrypt_key(
            encrypted_package.encrypted_session_key,
            recipient_private_key
        )

        # 2. Расшифровываем данные
        decrypted_data = self.hybrid_encryption.decrypt_bytes(
            encrypted_package.encrypted_data,
            decrypted_session_key
        )

        # 3. Десериализуем сообщение
        signed_message = deserialize_signed_message(decrypted_data)

        # 4. Проверяем цифровую подпись отправителя
        verify_check = self.rsa_signature.verify_detailed(
            signed_message.signature,
            signed_message.message,
            sender_public_key
        )

        return DecryptionResult(
            message=signed_message.message,
            is_signature_valid=verify_check.is_valid,
            decrypted_session_key=decrypted_session_key,
            decrypted_data=decrypted_data,
            verify_check=verify_check
        )

# from utils import generate_key
#
# from digital_signature import RsaSignature
# from hybrid_encryption import HybridEncryption
# from message_serializer import serialize_signed_message, deserialize_signed_message
# from models import EncryptedPackage, DecryptionResult, SignedMessage
#
#
# class HybridProtocol:
#
#     def __init__(self):
#         self.rsa_signature = RsaSignature()
#         self.hybrid_encryption = HybridEncryption()
#
#
#     def encrypt(
#             self,
#             message: str,
#             sender_private_key,
#             recipient_public_key
#     ) -> EncryptedPackage:
#
#         message_sign = self.rsa_signature.sign(message, sender_private_key)
#
#         signed_message = SignedMessage(
#             message = message,
#             signature= message_sign
#         )
#         bytes_data = serialize_signed_message(signed_message)
#
#         session_key = generate_key()
#
#         encrypted_data = self.hybrid_encryption.encrypt_bytes(
#             bytes_data, session_key
#         )
#         encrypted_session_key = self.hybrid_encryption.encrypt_key(recipient_public_key, session_key)
#
#         return EncryptedPackage(encrypted_data, encrypted_session_key)
#
#
#     def decrypt(
#             self,
#             encrypted_package: EncryptedPackage,
#             recipient_private_key: tuple[int, int],
#             sender_public_key: tuple[int, int]
#     ) -> DecryptionResult:
#
#         decrypted_session_key = self.hybrid_encryption.decrypt_key(
#             encrypted_package.encrypted_session_key, recipient_private_key
#         )
#
#         decrypted_data = self.hybrid_encryption.decrypt_bytes(
#             encrypted_package.encrypted_data, decrypted_session_key
#         )
#
#         signed_message = deserialize_signed_message(decrypted_data)
#
#         verify_sign = self.rsa_signature.verify(
#             signed_message.signature, signed_message.message, sender_public_key
#         )
#
#         return DecryptionResult(signed_message.message, verify_sign)


# from rsa import RSA
# ### Верная передача данных
# rsa_alice = RSA(130)
# rsa_signature_keypair = rsa_alice.generate_keypair()
#
# alice = HybridProtocol()
#
#
# rsa_bob = RSA(65)
# rsa_bob_keypair = rsa_bob.generate_keypair()
#
# encrypted_alice_data = alice.encrypt("ПРивет, Боб!",rsa_signature_keypair[1], rsa_bob_keypair[0])
#
# bob = HybridProtocol()
# decrypted_bob_data = bob.decrypt(encrypted_alice_data,rsa_bob_keypair[1], rsa_signature_keypair[0])
# print(encrypted_alice_data)
# print(decrypted_bob_data)
#
#
# ### Подмена открытого ключа подписи
# rsa_alice = RSA(130)
# rsa_signature_keypair = rsa_alice.generate_keypair()
# fake_key = rsa_alice.generate_keypair()
#
# alice = HybridProtocol()
#
#
# rsa_bob = RSA(65)
# rsa_bob_keypair = rsa_bob.generate_keypair()
# encrypted_alice_data = alice.encrypt("ПРивет, Боб!",rsa_signature_keypair[1], rsa_bob_keypair[0])
#
#
# bob = HybridProtocol()
# decrypted_bob_data = bob.decrypt(encrypted_alice_data,rsa_bob_keypair[1], fake_key[0])
#
# print(encrypted_alice_data)
# print(decrypted_bob_data)
#
#
# #### Подмена закрытого ключа Боба
#
# rsa_alice = RSA(130)
# rsa_signature_keypair = rsa_alice.generate_keypair()
#
# alice = HybridProtocol()
#
#
# rsa_bob = RSA(65)
# rsa_bob_keypair = rsa_bob.generate_keypair()
# fake_key = rsa_bob.generate_keypair()
# encrypted_alice_data = alice.encrypt("ПРивет, Боб!",rsa_signature_keypair[1], rsa_bob_keypair[0])
#
#
# bob = HybridProtocol()
# decrypted_bob_data = bob.decrypt(encrypted_alice_data, fake_key[1], rsa_signature_keypair[0])
#
# print(encrypted_alice_data)
# print(decrypted_bob_data)
#
# #### Изменение подписи до формирования зашифрованного пакета
# rsa_alice = RSA(130)
# rsa_signature_keypair = rsa_alice.generate_keypair()
# message = "Hello, Bob!"
# rsa_signature = RsaSignature()
# he = HybridEncryption()
#
# message_sign = rsa_signature.sign(message, rsa_signature_keypair[1])
#
# fake_signature_keypair = rsa_alice.generate_keypair()
# fake_sign = rsa_signature.sign(message+"1", fake_signature_keypair[1])
# signed_message = SignedMessage(
#     message=message,
#     signature=fake_sign
# )
# bytes_data = serialize_signed_message(signed_message)
#
# session_key = generate_key()
#
# encrypted_data = he.encrypt_bytes(
#     bytes_data, session_key
# )
#
# alice = HybridProtocol()
#
#
# rsa_bob = RSA(65)
# rsa_bob_keypair = rsa_bob.generate_keypair()
# encrypted_session_key = he.encrypt_key(rsa_bob_keypair[0], session_key)
# encrypted_alice_data = EncryptedPackage(encrypted_data, encrypted_session_key)
#
#
# bob = HybridProtocol()
# decrypted_bob_data = bob.decrypt(encrypted_alice_data, rsa_bob_keypair[1], rsa_signature_keypair[0])
#
# print(encrypted_alice_data)
# print(decrypted_bob_data)