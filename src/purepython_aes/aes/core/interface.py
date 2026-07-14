from abc import ABC, abstractmethod
from typing import ClassVar


class Aes(ABC):
    """Base class for AES-128, AES-192, and AES-256 algorithms."""

    __key_size__: ClassVar[int]
    """AES key length in bytes."""

    __round_count__: ClassVar[int]
    """Number of AES rounds."""

    @abstractmethod
    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 16-byte AES block."""

        raise NotImplementedError

    @abstractmethod
    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 16-byte AES block."""

        raise NotImplementedError

    @abstractmethod
    def __init__(self, key: bytes) -> None:
        raise NotImplementedError
