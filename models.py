from dataclasses import dataclass


@dataclass
class SignedMessage:
    message: str
    signature: str


@dataclass
class EncryptedPackage:
    encrypted_data: str
    encrypted_session_key: str


@dataclass
class EncryptionResult:
    package: EncryptedPackage
    signature_result: "SignatureResult"
    signed_message_json: bytes
    session_key: tuple[int, int, int, int]


@dataclass
class DecryptionResult:
    message: str
    is_signature_valid: bool
    decrypted_session_key: tuple
    decrypted_data: bytes
    verify_check: "VerifyCheck"


@dataclass
class SignatureResult:
    message_hash: bytes
    hash_hex: str
    int_message: int
    int_sign: int
    b64_sign: str


@dataclass
class VerifyCheck:
    message_hash: bytes
    hash_hex: str
    int_message: int
    int_sign: int
    sign_hash: int
    is_valid: bool


# from dataclasses import dataclass
#
#
# @dataclass
# class SignedMessage:
#     message: str
#     signature: str
#
#
# @dataclass
# class EncryptedPackage:
#     encrypted_data: str
#     encrypted_session_key: str
#
#
# @dataclass
# class DecryptionResult:
#     message: str
#     is_signature_valid: bool
#
#
# @dataclass
# class SignatureResult:
#     message_hash: bytes
#     hash_hex: str
#     int_message: int
#     int_sign: int
#     b64_sign: str
#
# @dataclass
# class VerifyCheck:
#     message_hash: bytes
#     hash_hex: str
#     int_message: int
#     int_sign: int
#     sign_hash: int
#     is_valid: bool