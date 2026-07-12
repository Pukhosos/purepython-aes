from typing import Final

from hypothesis.strategies import binary, builds, SearchStrategy

from purepython_aes.aes.algorithms import Aes128, Aes192, Aes256
from purepython_aes.const import AES_128_KEY_SIZE, AES_192_KEY_SIZE, AES_256_KEY_SIZE

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

aes128: Final[SearchStrategy[Aes128]] = builds(Aes128, aes128key)
aes192: Final[SearchStrategy[Aes192]] = builds(Aes192, aes192key)
aes256: Final[SearchStrategy[Aes256]] = builds(Aes256, aes256key)
