from typing import Final

from hypothesis.strategies import binary, integers, SearchStrategy

from purepython_aes.const import (
    AES_128_KEY_SIZE,
    AES_192_KEY_SIZE,
    AES_256_KEY_SIZE,
    AES_BLOCK_SIZE,
)

byte_values: Final[SearchStrategy[int]] = integers(min_value=0x00, max_value=0xFF)

aes128key: Final[SearchStrategy[bytes]] = binary(
    min_size=AES_128_KEY_SIZE,
    max_size=AES_128_KEY_SIZE,
)
aes192key: Final[SearchStrategy[bytes]] = binary(
    min_size=AES_192_KEY_SIZE,
    max_size=AES_192_KEY_SIZE,
)
aes256key: Final[SearchStrategy[bytes]] = binary(
    min_size=AES_256_KEY_SIZE,
    max_size=AES_256_KEY_SIZE,
)

aes_blocks: Final[SearchStrategy[bytes]] = binary(
    min_size=AES_BLOCK_SIZE,
    max_size=AES_BLOCK_SIZE,
)
