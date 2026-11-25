import base64
import struct
from os import urandom

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

MAGIC = b"STEGOV1"
SALT_SIZE = 16
LENGTH_SIZE = 4
RGB_CHANNELS = 3
RGBA_CHANNELS = 4
PBKDF2_ITERATIONS = 390_000


class StegoError(ValueError):
    """Raised when a hidden message cannot be encoded or decoded."""


def _fernet_for_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)


def _payload_bits(payload):
    for value in payload:
        for shift in range(7, -1, -1):
            yield (value >> shift) & 1


def encode_message(image, message, password):
    """Encrypt a message and store it in RGB least-significant bits."""
    salt = urandom(SALT_SIZE)
    token = _fernet_for_password(password, salt).encrypt(message.encode("utf-8"))
    payload = MAGIC + salt + token
    framed_payload = struct.pack(">I", len(payload)) + payload
    required_bits = len(framed_payload) * 8
    rgba_image = image.convert("RGBA")
    pixels = bytearray(rgba_image.tobytes())
    pixel_count = rgba_image.width * rgba_image.height

    if required_bits > pixel_count * RGB_CHANNELS:
        raise StegoError("This image is too small to hold the encrypted message.")

    for bit_index, bit in enumerate(_payload_bits(framed_payload)):
        pixel_index, channel_index = divmod(bit_index, RGB_CHANNELS)
        byte_index = pixel_index * RGBA_CHANNELS + channel_index
        pixels[byte_index] = (pixels[byte_index] & 0xFE) | bit

    return Image.frombytes("RGBA", rgba_image.size, bytes(pixels))


def _read_bytes(pixels, start_bit, byte_count):
    result = bytearray()
    value = 0
    for bit_index in range(start_bit, start_bit + byte_count * 8):
        pixel_index, channel_index = divmod(bit_index, RGB_CHANNELS)
        byte_index = pixel_index * RGBA_CHANNELS + channel_index
        value = (value << 1) | (pixels[byte_index] & 1)
        if (bit_index - start_bit) % 8 == 7:
            result.append(value)
            value = 0
    return bytes(result)


def decode_message(image, password):
    """Read, validate, and decrypt a message from an RGB image."""
    rgba_image = image.convert("RGBA")
    pixels = rgba_image.tobytes()
    pixel_count = rgba_image.width * rgba_image.height
    available_bits = pixel_count * RGB_CHANNELS
    if available_bits < LENGTH_SIZE * 8:
        raise StegoError("This image does not contain a hidden message.")

    payload_length = struct.unpack(">I", _read_bytes(pixels, 0, LENGTH_SIZE))[0]
    available_bytes = available_bits // 8 - LENGTH_SIZE
    if payload_length < len(MAGIC) + SALT_SIZE or payload_length > available_bytes:
        raise StegoError("This image does not contain a valid PhotoLock message.")

    payload = _read_bytes(pixels, LENGTH_SIZE * 8, payload_length)
    if not payload.startswith(MAGIC):
        raise StegoError("This image does not contain a PhotoLock message.")

    salt_start = len(MAGIC)
    salt = payload[salt_start : salt_start + SALT_SIZE]
    token = payload[salt_start + SALT_SIZE :]
    try:
        plaintext = _fernet_for_password(password, salt).decrypt(token)
        return plaintext.decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise StegoError("The password is incorrect or the hidden data is damaged.") from exc
