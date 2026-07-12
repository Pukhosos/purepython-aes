from typing import Final

from hypothesis.strategies import binary, SearchStrategy

from purepython_aes.const import AES_BLOCK_SIZE

aes_blocks: Final[SearchStrategy[bytes]] = binary(
    min_size=AES_BLOCK_SIZE,
    max_size=AES_BLOCK_SIZE,
)
