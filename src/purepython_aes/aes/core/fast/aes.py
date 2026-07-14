from dataclasses import dataclass

from purepython_aes.aes.core.fast.expansion import (
    expand_aes128_key,
    expand_aes192_key,
    expand_aes256_key,
)
from purepython_aes.aes.core.fast.keys import (
    build_decryption_round_keys,
    RoundKey,
    RoundKeys,
)
from purepython_aes.aes.core.fast.ttables import (
    DECRYPTION_TABLE_0,
    DECRYPTION_TABLE_1,
    DECRYPTION_TABLE_2,
    DECRYPTION_TABLE_3,
    ENCRYPTION_TABLE_0,
    ENCRYPTION_TABLE_1,
    ENCRYPTION_TABLE_2,
    ENCRYPTION_TABLE_3,
)
from purepython_aes.aes.core.interface import Aes
from purepython_aes.const import (
    AES_128_KEY_SIZE,
    AES_192_KEY_SIZE,
    AES_256_KEY_SIZE,
    AES_BLOCK_SIZE,
    INVERSE_SBOX,
    SBOX,
)


@dataclass(init=False, slots=True)
class FastAesCore(Aes):
    """Implement optimized `encrypt_block` and `decrypt_block` methods."""

    __decryption_round_keys: RoundKeys
    __encryption_round_keys: RoundKeys

    def __init__(self, key: bytes) -> None:
        if len(key) != self.__key_size__:
            raise ValueError(
                f'expected len(key) == {self.__key_size__}, got {len(key)}'
            )
        key_size: int = len(key)
        if key_size == AES_128_KEY_SIZE:
            self.__encryption_round_keys = expand_aes128_key(key)
        if key_size == AES_192_KEY_SIZE:
            self.__encryption_round_keys = expand_aes192_key(key)
        if key_size == AES_256_KEY_SIZE:
            self.__encryption_round_keys = expand_aes256_key(key)
        self.__decryption_round_keys = build_decryption_round_keys(
            self.__encryption_round_keys
        )

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 16-byte block using fused T-table rounds."""

        if len(plaintext) != AES_BLOCK_SIZE:
            raise ValueError(
                f'expected len(plaintext) == {AES_BLOCK_SIZE}, got {len(plaintext)}'
            )
        round_keys: RoundKeys = self.__encryption_round_keys
        plaintext_integer: int = int.from_bytes(plaintext, byteorder='big')
        initial_round_key: RoundKey = round_keys[0]
        state_0: int = (plaintext_integer >> 96) ^ initial_round_key[0]
        state_1: int = ((plaintext_integer >> 64) & 0xFFFFFFFF) ^ initial_round_key[1]
        state_2: int = ((plaintext_integer >> 32) & 0xFFFFFFFF) ^ initial_round_key[2]
        state_3: int = (plaintext_integer & 0xFFFFFFFF) ^ initial_round_key[3]
        for round_index in range(1, self.__round_count__):
            round_key: RoundKey = round_keys[round_index]
            next_state_0: int = (
                ENCRYPTION_TABLE_0[(state_0 >> 24) & 0xFF]
                ^ ENCRYPTION_TABLE_1[(state_1 >> 16) & 0xFF]
                ^ ENCRYPTION_TABLE_2[(state_2 >> 8) & 0xFF]
                ^ ENCRYPTION_TABLE_3[state_3 & 0xFF]
                ^ round_key[0]
            )
            next_state_1: int = (
                ENCRYPTION_TABLE_0[(state_1 >> 24) & 0xFF]
                ^ ENCRYPTION_TABLE_1[(state_2 >> 16) & 0xFF]
                ^ ENCRYPTION_TABLE_2[(state_3 >> 8) & 0xFF]
                ^ ENCRYPTION_TABLE_3[state_0 & 0xFF]
                ^ round_key[1]
            )
            next_state_2: int = (
                ENCRYPTION_TABLE_0[(state_2 >> 24) & 0xFF]
                ^ ENCRYPTION_TABLE_1[(state_3 >> 16) & 0xFF]
                ^ ENCRYPTION_TABLE_2[(state_0 >> 8) & 0xFF]
                ^ ENCRYPTION_TABLE_3[state_1 & 0xFF]
                ^ round_key[2]
            )
            next_state_3: int = (
                ENCRYPTION_TABLE_0[(state_3 >> 24) & 0xFF]
                ^ ENCRYPTION_TABLE_1[(state_0 >> 16) & 0xFF]
                ^ ENCRYPTION_TABLE_2[(state_1 >> 8) & 0xFF]
                ^ ENCRYPTION_TABLE_3[state_2 & 0xFF]
                ^ round_key[3]
            )
            state_0 = next_state_0
            state_1 = next_state_1
            state_2 = next_state_2
            state_3 = next_state_3
        final_round_key: RoundKey = round_keys[self.__round_count__]
        output_0: int = (
            (SBOX[(state_0 >> 24) & 0xFF] << 24)
            | (SBOX[(state_1 >> 16) & 0xFF] << 16)
            | (SBOX[(state_2 >> 8) & 0xFF] << 8)
            | SBOX[state_3 & 0xFF]
        ) ^ final_round_key[0]
        output_1: int = (
            (SBOX[(state_1 >> 24) & 0xFF] << 24)
            | (SBOX[(state_2 >> 16) & 0xFF] << 16)
            | (SBOX[(state_3 >> 8) & 0xFF] << 8)
            | SBOX[state_0 & 0xFF]
        ) ^ final_round_key[1]
        output_2: int = (
            (SBOX[(state_2 >> 24) & 0xFF] << 24)
            | (SBOX[(state_3 >> 16) & 0xFF] << 16)
            | (SBOX[(state_0 >> 8) & 0xFF] << 8)
            | SBOX[state_1 & 0xFF]
        ) ^ final_round_key[2]
        output_3: int = (
            (SBOX[(state_3 >> 24) & 0xFF] << 24)
            | (SBOX[(state_0 >> 16) & 0xFF] << 16)
            | (SBOX[(state_1 >> 8) & 0xFF] << 8)
            | SBOX[state_2 & 0xFF]
        ) ^ final_round_key[3]
        output_integer: int = (
            (output_0 << 96) | (output_1 << 64) | (output_2 << 32) | output_3
        )
        return output_integer.to_bytes(AES_BLOCK_SIZE, byteorder='big')

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one block using equivalent-inverse T-table rounds."""

        if len(ciphertext) != AES_BLOCK_SIZE:
            raise ValueError(
                f'expected len(ciphertext) == {AES_BLOCK_SIZE}, got {len(ciphertext)}'
            )
        round_keys: RoundKeys = self.__decryption_round_keys
        ciphertext_integer: int = int.from_bytes(
            ciphertext,
            byteorder='big',
        )
        initial_round_key: RoundKey = round_keys[0]
        state_0: int = (ciphertext_integer >> 96) ^ initial_round_key[0]
        state_1: int = ((ciphertext_integer >> 64) & 0xFFFFFFFF) ^ initial_round_key[1]
        state_2: int = ((ciphertext_integer >> 32) & 0xFFFFFFFF) ^ initial_round_key[2]
        state_3: int = (ciphertext_integer & 0xFFFFFFFF) ^ initial_round_key[3]
        for round_index in range(1, self.__round_count__):
            round_key: RoundKey = round_keys[round_index]
            next_state_0: int = (
                DECRYPTION_TABLE_0[(state_0 >> 24) & 0xFF]
                ^ DECRYPTION_TABLE_1[(state_3 >> 16) & 0xFF]
                ^ DECRYPTION_TABLE_2[(state_2 >> 8) & 0xFF]
                ^ DECRYPTION_TABLE_3[state_1 & 0xFF]
                ^ round_key[0]
            )
            next_state_1: int = (
                DECRYPTION_TABLE_0[(state_1 >> 24) & 0xFF]
                ^ DECRYPTION_TABLE_1[(state_0 >> 16) & 0xFF]
                ^ DECRYPTION_TABLE_2[(state_3 >> 8) & 0xFF]
                ^ DECRYPTION_TABLE_3[state_2 & 0xFF]
                ^ round_key[1]
            )
            next_state_2: int = (
                DECRYPTION_TABLE_0[(state_2 >> 24) & 0xFF]
                ^ DECRYPTION_TABLE_1[(state_1 >> 16) & 0xFF]
                ^ DECRYPTION_TABLE_2[(state_0 >> 8) & 0xFF]
                ^ DECRYPTION_TABLE_3[state_3 & 0xFF]
                ^ round_key[2]
            )
            next_state_3: int = (
                DECRYPTION_TABLE_0[(state_3 >> 24) & 0xFF]
                ^ DECRYPTION_TABLE_1[(state_2 >> 16) & 0xFF]
                ^ DECRYPTION_TABLE_2[(state_1 >> 8) & 0xFF]
                ^ DECRYPTION_TABLE_3[state_0 & 0xFF]
                ^ round_key[3]
            )
            state_0 = next_state_0
            state_1 = next_state_1
            state_2 = next_state_2
            state_3 = next_state_3
        final_round_key: RoundKey = round_keys[self.__round_count__]
        output_0: int = (
            (INVERSE_SBOX[(state_0 >> 24) & 0xFF] << 24)
            | (INVERSE_SBOX[(state_3 >> 16) & 0xFF] << 16)
            | (INVERSE_SBOX[(state_2 >> 8) & 0xFF] << 8)
            | INVERSE_SBOX[state_1 & 0xFF]
        ) ^ final_round_key[0]
        output_1: int = (
            (INVERSE_SBOX[(state_1 >> 24) & 0xFF] << 24)
            | (INVERSE_SBOX[(state_0 >> 16) & 0xFF] << 16)
            | (INVERSE_SBOX[(state_3 >> 8) & 0xFF] << 8)
            | INVERSE_SBOX[state_2 & 0xFF]
        ) ^ final_round_key[1]
        output_2: int = (
            (INVERSE_SBOX[(state_2 >> 24) & 0xFF] << 24)
            | (INVERSE_SBOX[(state_1 >> 16) & 0xFF] << 16)
            | (INVERSE_SBOX[(state_0 >> 8) & 0xFF] << 8)
            | INVERSE_SBOX[state_3 & 0xFF]
        ) ^ final_round_key[2]
        output_3: int = (
            (INVERSE_SBOX[(state_3 >> 24) & 0xFF] << 24)
            | (INVERSE_SBOX[(state_2 >> 16) & 0xFF] << 16)
            | (INVERSE_SBOX[(state_1 >> 8) & 0xFF] << 8)
            | INVERSE_SBOX[state_0 & 0xFF]
        ) ^ final_round_key[3]
        output_integer: int = (
            (output_0 << 96) | (output_1 << 64) | (output_2 << 32) | output_3
        )
        return output_integer.to_bytes(AES_BLOCK_SIZE, byteorder='big')
