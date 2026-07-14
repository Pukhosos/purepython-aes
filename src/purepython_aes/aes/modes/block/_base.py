from abc import ABC, abstractmethod
from dataclasses import dataclass

from purepython_aes.aes.modes._base import CipherMode
from purepython_aes.aes.padding import BasePadding
from purepython_aes.const import AES_BLOCK_SIZE


@dataclass(slots=True)
class BlockCipherMode(CipherMode, ABC):
    padding: BasePadding

    @abstractmethod
    def __encrypt_blocks__(self, padded_plaintext: bytes) -> bytes:
        """Encrypt plaintext containing complete blocks."""

        raise NotImplementedError

    @abstractmethod
    def __decrypt_blocks__(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext containing complete blocks."""

        raise NotImplementedError

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.__encrypt_blocks__(self.padding.pad(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % AES_BLOCK_SIZE != 0:
            raise ValueError(f'len(ciphertext) % {AES_BLOCK_SIZE} must be 0')
        return self.padding.unpad(self.__decrypt_blocks__(ciphertext))
