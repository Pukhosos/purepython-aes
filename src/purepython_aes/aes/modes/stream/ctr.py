# src/purepython_aes/aes/modes/stream/ctr.py
from dataclasses import dataclass
from typing import final

from purepython_aes.aes.modes.operations import xor
from purepython_aes.aes.modes.stream._base import StreamCipherMode
from purepython_aes.const import AES_BLOCK_SIZE


@final
@dataclass(slots=True)
class CtrMode(StreamCipherMode):
    """Counter mode of operation."""

    def __encrypt_stream__(
        self,
        initialization_value: bytes,
        plaintext: bytes,
    ) -> bytes:
        return self.transform(initialization_value, plaintext)

    def __decrypt_stream__(
        self,
        initialization_value: bytes,
        ciphertext: bytes,
    ) -> bytes:
        return self.transform(initialization_value, ciphertext)

    def transform(
        self,
        initialization_value: bytes,
        data: bytes,
    ) -> bytes:
        """XOR data with the counter-generated keystream."""

        block_count: int = (len(data) + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE
        initial_counter: int = int.from_bytes(initialization_value, byteorder='big')
        transformed_data: bytearray = bytearray()
        for block_index in range(block_count):
            block_start: int = block_index * AES_BLOCK_SIZE
            data_block: bytes = data[block_start : (block_start + AES_BLOCK_SIZE)]
            counter: int = (initial_counter + block_index) % 2 ** (AES_BLOCK_SIZE * 8)
            counter_block: bytes = counter.to_bytes(AES_BLOCK_SIZE, byteorder='big')
            keystream_block: bytes = self.algorithm.encrypt_block(counter_block)
            transformed_block: bytes = xor(
                data_block,
                keystream_block[: len(data_block)],
            )
            transformed_data.extend(transformed_block)
        return bytes(transformed_data)
