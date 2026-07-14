from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from purepython_aes.aes.core.interface import Aes


@dataclass
class AesMode(ABC):
    """Base class for all AES modes of operation."""

    algorithm: Aes
    """Either AES-128, AES-192, or AES-256."""


@dataclass
class CipherMode(AesMode):
    """Base class for all AES Cipher modes of operation."""

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a byte string."""

        raise NotImplementedError

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt a byte string."""

        raise NotImplementedError
