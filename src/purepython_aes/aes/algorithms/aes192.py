from purepython_aes.aes.core import AesCore
from purepython_aes.const import AES_192_KEY_SIZE, AES_192_ROUND_COUNT


class Aes192(AesCore):
    """AES-192 encryption algorithm."""

    @property
    def key_size(self) -> int:
        return AES_192_KEY_SIZE

    @property
    def round_count(self) -> int:
        return AES_192_ROUND_COUNT
