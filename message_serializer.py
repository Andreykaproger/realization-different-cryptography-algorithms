import json

from dataclasses import asdict

from models import SignedMessage


def serialize_signed_message(signed_message: SignedMessage) -> bytes:
    json_signed_message = json.dumps(asdict(signed_message), ensure_ascii=False)

    json_bytes = json_signed_message.encode("utf-8")

    return json_bytes


def deserialize_signed_message(json_bytes: bytes) -> SignedMessage:
    json_message = json_bytes.decode("utf-8")

    json_signed_message = json.loads(json_message)

    return SignedMessage(**json_signed_message)