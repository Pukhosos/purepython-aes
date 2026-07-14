from typing import Final

from hypothesis.strategies import binary, integers, one_of, SearchStrategy

from purepython_aes.const import AES_256_KEY_SIZE, AES_BLOCK_SIZE

MAX_PROPERTY_DATA_SIZE: Final[int] = AES_BLOCK_SIZE * 8
MAX_PROPERTY_BLOCK_COUNT: Final[int] = 8
MAX_COUNTER_VALUE: Final[int] = (1 << (AES_BLOCK_SIZE * 8)) - 1

aes256key: Final[SearchStrategy[bytes]] = binary(
    min_size=AES_256_KEY_SIZE,
    max_size=AES_256_KEY_SIZE,
)
aes_blocks: Final[SearchStrategy[bytes]] = binary(
    min_size=AES_BLOCK_SIZE,
    max_size=AES_BLOCK_SIZE,
)
arbitrary_aes_blocks: Final[SearchStrategy[bytes]] = binary(
    min_size=0,
    max_size=MAX_PROPERTY_DATA_SIZE,
)
aligned_aes_blocks: Final[SearchStrategy[bytes]] = one_of(
    *tuple(
        binary(
            min_size=(block_count * AES_BLOCK_SIZE),
            max_size=(block_count * AES_BLOCK_SIZE),
        )
        for block_count in range(MAX_PROPERTY_BLOCK_COUNT + 1)
    )
)
counters: Final[SearchStrategy[int]] = integers(
    min_value=0,
    max_value=MAX_COUNTER_VALUE,
)
rollover_counters: Final[SearchStrategy[int]] = integers(
    min_value=(MAX_COUNTER_VALUE - MAX_PROPERTY_BLOCK_COUNT),
    max_value=MAX_COUNTER_VALUE,
)
rollover_aes_blocks: Final[SearchStrategy[bytes]] = binary(
    min_size=(AES_BLOCK_SIZE + 1),
    max_size=MAX_PROPERTY_DATA_SIZE,
)
