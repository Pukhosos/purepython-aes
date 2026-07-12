from purepython_aes.aes.core import AesCore
from purepython_aes.const import AES_256_KEY_SIZE, AES_256_ROUND_COUNT


class Aes256(AesCore):
    """AES-256 encryption algorithm."""

    @property
    def key_size(self) -> int:
        return AES_256_KEY_SIZE

    @property
    def round_count(self) -> int:
        return AES_256_ROUND_COUNT
