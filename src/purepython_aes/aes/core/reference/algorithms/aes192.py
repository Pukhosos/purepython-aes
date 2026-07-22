from dataclasses import dataclass
from typing import ClassVar

from purepython_aes.aes.core.reference.aes import ReferenceAesCore
from purepython_aes.const import AES_192_KEY_SIZE, AES_192_ROUND_COUNT


@dataclass(init=False, slots=True)
class ReferenceAes192(ReferenceAesCore):
    """AES-192 encryption algorithm."""

    __key_size__: ClassVar[int] = AES_192_KEY_SIZE
    __round_count__: ClassVar[int] = AES_192_ROUND_COUNT
