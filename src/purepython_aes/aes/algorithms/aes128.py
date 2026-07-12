from purepython_aes.aes.core import AesCore
from purepython_aes.const import AES_128_KEY_SIZE, AES_128_ROUND_COUNT


class Aes128(AesCore):
    """AES-128 encryption algorithm."""

    @property
    def key_size(self) -> int:
        return AES_128_KEY_SIZE

    @property
    def round_count(self) -> int:
        return AES_128_ROUND_COUNT
