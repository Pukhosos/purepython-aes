from dataclasses import dataclass
from typing import final

from purepython_aes.aes.modes.block._base import BlockCipherMode
from purepython_aes.aes.modes.operations import split_into_blocks


@final
@dataclass(slots=True)
class EcbMode(BlockCipherMode):
    """Electronic Codebook mode of operation."""

    def encrypt_blocks(self, padded_plaintext: bytes) -> bytes:
        return bytes(0).join(
            map(self.algorithm.encrypt_block, split_into_blocks(padded_plaintext))
        )

    def decrypt_blocks(self, ciphertext: bytes) -> bytes:
        return bytes(0).join(
            map(self.algorithm.decrypt_block, split_into_blocks(ciphertext))
        )
