from dataclasses import dataclass

from purepython_aes.aes.core.interface import Aes
from purepython_aes.aes.core.reference.expansion import expand_key
from purepython_aes.aes.core.reference.state import AesState
from purepython_aes.const import AES_BLOCK_SIZE


@dataclass(init=False, slots=True)
class AesCore(Aes):
    """Implement `encrypt_block` and `decrypt_block` methods."""

    __round_keys: tuple[bytes, ...]

    def __init__(self, key: bytes) -> None:
        if len(key) != self.__key_size__:
            raise ValueError(
                f'expected len(key) == {self.__key_size__}, got {len(key)}'
            )
        self.__round_keys = expand_key(key, self.__round_count__)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != AES_BLOCK_SIZE:
            raise ValueError(
                f'Expected len(plaintext) == {AES_BLOCK_SIZE}, got {len(plaintext)}'
            )
        state: AesState = AesState.from_bytes(plaintext)
        state.add_round_key(self.__round_keys[0])
        for round_index in range(1, self.__round_count__):
            state.subs_bytes()
            state.shift_rows()
            state.mix_columns()
            state.add_round_key(self.__round_keys[round_index])
        state.subs_bytes()
        state.shift_rows()
        state.add_round_key(self.__round_keys[self.__round_count__])
        return state.to_bytes()

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != AES_BLOCK_SIZE:
            raise ValueError(
                f'Expected len(ciphertext) == {AES_BLOCK_SIZE}, got {len(ciphertext)}'
            )
        state: AesState = AesState.from_bytes(ciphertext)
        state.add_round_key(self.__round_keys[self.__round_count__])
        for round_index in range(self.__round_count__ - 1, 0, -1):
            state.inverse_shift_rows()
            state.inverse_subs_bytes()
            state.add_round_key(self.__round_keys[round_index])
            state.inverse_mix_columns()
        state.inverse_shift_rows()
        state.inverse_subs_bytes()
        state.add_round_key(self.__round_keys[0])
        return state.to_bytes()
