from collections.abc import Callable
from typing import Any, cast, Final

from pyaes import (  # type: ignore[import-untyped]
    AES,
    AESModeOfOperationCBC,
    AESModeOfOperationCFB,
    AESModeOfOperationCTR,
    AESModeOfOperationECB,
    AESModeOfOperationOFB,
    Counter,
    Decrypter,
    Encrypter,
)

from purepython_aes.const import AES_BLOCK_SIZE
from purepython_aes.types import CfbSegmentSize

PYAES_DEFAULT_PADDING: Final[str] = 'default'


def encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt one block with the pyaes AES primitive."""

    reference_algorithm: Any = AES(key)
    ciphertext: list[int] = cast(list[int], reference_algorithm.encrypt(plaintext))
    return bytes(ciphertext)


def decrypt_block(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt one block with the pyaes AES primitive."""

    reference_algorithm: Any = AES(key)
    plaintext: list[int] = cast(list[int], reference_algorithm.decrypt(ciphertext))
    return bytes(plaintext)


def encrypt_ecb_without_padding(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt complete blocks with pyaes ECB and no padding."""

    reference_mode: Any = AESModeOfOperationECB(key)
    transform: Callable[[bytes], bytes] = cast(
        Callable[[bytes], bytes],
        reference_mode.encrypt,
    )
    return transform_blocks(transform, plaintext)


def decrypt_ecb_without_padding(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt complete blocks with pyaes ECB and no padding."""

    reference_mode: Any = AESModeOfOperationECB(key)
    transform: Callable[[bytes], bytes] = cast(
        Callable[[bytes], bytes],
        reference_mode.decrypt,
    )
    return transform_blocks(transform, ciphertext)


def encrypt_ecb_with_pkcs7(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt arbitrary data with pyaes ECB and PKCS#7 padding."""

    reference_mode: Any = AESModeOfOperationECB(key)
    reference_encrypter: Any = Encrypter(
        reference_mode,
        padding=PYAES_DEFAULT_PADDING,
    )
    return feed_and_finalize(reference_encrypter, plaintext)


def decrypt_ecb_with_pkcs7(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and unpad pyaes ECB ciphertext."""

    reference_mode: Any = AESModeOfOperationECB(key)
    reference_decrypter: Any = Decrypter(
        reference_mode,
        padding=PYAES_DEFAULT_PADDING,
    )
    return feed_and_finalize(reference_decrypter, ciphertext)


def encrypt_cbc_without_padding(
    key: bytes,
    initialization_value: bytes,
    plaintext: bytes,
) -> bytes:
    """Encrypt complete blocks with pyaes CBC and no padding."""

    reference_mode: Any = AESModeOfOperationCBC(key, iv=initialization_value)
    transform: Callable[[bytes], bytes] = cast(
        Callable[[bytes], bytes],
        reference_mode.encrypt,
    )
    return transform_blocks(transform, plaintext)


def decrypt_cbc_without_padding(
    key: bytes,
    initialization_value: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt complete blocks with pyaes CBC and no padding."""

    reference_mode: Any = AESModeOfOperationCBC(key, iv=initialization_value)
    transform: Callable[[bytes], bytes] = cast(
        Callable[[bytes], bytes],
        reference_mode.decrypt,
    )
    return transform_blocks(transform, ciphertext)


def encrypt_cbc_with_pkcs7(
    key: bytes,
    initialization_value: bytes,
    plaintext: bytes,
) -> bytes:
    """Encrypt arbitrary data with pyaes CBC and PKCS#7 padding."""

    reference_mode: Any = AESModeOfOperationCBC(key, iv=initialization_value)
    reference_encrypter: Any = Encrypter(
        reference_mode,
        padding=PYAES_DEFAULT_PADDING,
    )
    return feed_and_finalize(reference_encrypter, plaintext)


def decrypt_cbc_with_pkcs7(
    key: bytes,
    initialization_value: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt and unpad pyaes CBC ciphertext."""

    reference_mode: Any = AESModeOfOperationCBC(key, iv=initialization_value)
    reference_decrypter: Any = Decrypter(
        reference_mode,
        padding=PYAES_DEFAULT_PADDING,
    )
    return feed_and_finalize(reference_decrypter, ciphertext)


def encrypt_cfb(
    key: bytes,
    initialization_value: bytes,
    segment_size: CfbSegmentSize,
    plaintext: bytes,
) -> bytes:
    """Encrypt arbitrary data with pyaes CFB."""

    reference_mode: Any = AESModeOfOperationCFB(
        key,
        iv=initialization_value,
        segment_size=segment_size,
    )
    reference_encrypter: Any = Encrypter(reference_mode)
    return feed_and_finalize(reference_encrypter, plaintext)


def decrypt_cfb(
    key: bytes,
    initialization_value: bytes,
    segment_size: CfbSegmentSize,
    ciphertext: bytes,
) -> bytes:
    """Decrypt arbitrary data with pyaes CFB."""

    reference_mode: Any = AESModeOfOperationCFB(
        key,
        iv=initialization_value,
        segment_size=segment_size,
    )
    reference_decrypter: Any = Decrypter(reference_mode)
    return feed_and_finalize(reference_decrypter, ciphertext)


def encrypt_ofb(
    key: bytes,
    initialization_value: bytes,
    plaintext: bytes,
) -> bytes:
    """Encrypt arbitrary data with pyaes OFB."""

    reference_mode: Any = AESModeOfOperationOFB(key, iv=initialization_value)
    return cast(bytes, reference_mode.encrypt(plaintext))


def decrypt_ofb(
    key: bytes,
    initialization_value: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt arbitrary data with pyaes OFB."""

    reference_mode: Any = AESModeOfOperationOFB(key, iv=initialization_value)
    return cast(bytes, reference_mode.decrypt(ciphertext))


def encrypt_ctr(key: bytes, counter: int, plaintext: bytes) -> bytes:
    """Encrypt arbitrary data with a pyaes 128-bit counter."""

    reference_counter: Any = Counter(initial_value=counter)
    reference_mode: Any = AESModeOfOperationCTR(key, counter=reference_counter)
    return cast(bytes, reference_mode.encrypt(plaintext))


def decrypt_ctr(key: bytes, counter: int, ciphertext: bytes) -> bytes:
    """Decrypt arbitrary data with a pyaes 128-bit counter."""

    reference_counter: Any = Counter(initial_value=counter)
    reference_mode: Any = AESModeOfOperationCTR(key, counter=reference_counter)
    return cast(bytes, reference_mode.decrypt(ciphertext))


def transform_blocks(
    transform: Callable[[bytes], bytes],
    data: bytes,
) -> bytes:
    """Apply a stateful pyaes block transform to complete AES blocks."""

    if len(data) % AES_BLOCK_SIZE != 0:
        raise ValueError('data must contain complete AES blocks')

    transformed_blocks: list[bytes] = []
    for block_start in range(0, len(data), AES_BLOCK_SIZE):
        block_end: int = block_start + AES_BLOCK_SIZE
        transformed_block: bytes = transform(data[block_start:block_end])
        transformed_blocks.append(transformed_block)
    return bytes(0).join(transformed_blocks)


def feed_and_finalize(feeder: Any, data: bytes) -> bytes:
    """Feed all data to a pyaes BlockFeeder and finalize it."""

    transformed_data: bytes = cast(bytes, feeder.feed(data))
    final_data: bytes = cast(bytes, feeder.feed())
    return transformed_data + final_data
