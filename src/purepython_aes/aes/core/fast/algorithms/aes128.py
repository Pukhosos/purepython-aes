from dataclasses import dataclass
from typing import ClassVar

from purepython_aes.aes.core.fast.aes import FastAesCore
from purepython_aes.const import AES_128_KEY_SIZE, AES_128_ROUND_COUNT


@dataclass(init=False, slots=True)
class Aes128(FastAesCore):
    """AES-128 encryption algorithm."""

    __key_size__: ClassVar[int] = AES_128_KEY_SIZE
    __round_count__: ClassVar[int] = AES_128_ROUND_COUNT
