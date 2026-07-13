from abc import ABC, abstractmethod
from dataclasses import dataclass

from purepython_aes.aes.modes._base import AesMode
from purepython_aes.aes.padding import BasePadding
from purepython_aes.const import AES_BLOCK_SIZE


@dataclass(slots=True)
class BlockCipherMode(AesMode, ABC):
    padding: BasePadding

    @abstractmethod
    def encrypt_blocks(self, padded_plaintext: bytes) -> bytes:
        """Encrypt plaintext containing complete blocks."""

        raise NotImplementedError

    @abstractmethod
    def decrypt_blocks(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext containing complete blocks."""

        raise NotImplementedError

    def encrypt(self, plaintext: bytes) -> bytes:
        """Pad and encrypt a byte string."""

        return self.encrypt_blocks(self.padding.pad(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt and unpad a byte string."""

        if len(ciphertext) % AES_BLOCK_SIZE != 0:
            raise ValueError(f'len(ciphertext) % {AES_BLOCK_SIZE} must be 0')
        return self.padding.unpad(self.decrypt_blocks(ciphertext))
