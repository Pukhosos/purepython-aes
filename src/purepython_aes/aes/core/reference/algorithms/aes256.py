from dataclasses import dataclass
from typing import ClassVar

from purepython_aes.aes.core.reference.aes import ReferenceAesCore
from purepython_aes.const import AES_256_KEY_SIZE, AES_256_ROUND_COUNT


@dataclass(init=False, slots=True)
class ReferenceAes256(ReferenceAesCore):
    """AES-256 encryption algorithm."""

    __key_size__: ClassVar[int] = AES_256_KEY_SIZE
    __round_count__: ClassVar[int] = AES_256_ROUND_COUNT
