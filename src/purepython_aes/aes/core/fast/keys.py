from purepython_aes.aes.core.fast.ttables import (
    DECRYPTION_TABLE_0,
    DECRYPTION_TABLE_1,
    DECRYPTION_TABLE_2,
    DECRYPTION_TABLE_3,
)
from purepython_aes.const import SBOX
from purepython_aes.types import RoundKey, RoundKeys


def build_decryption_round_keys(
    encryption_round_keys: RoundKeys,
) -> RoundKeys:
    """Build the equivalent-inverse decryption key schedule."""

    round_count: int = len(encryption_round_keys) - 1
    decryption_round_keys: list[RoundKey] = [encryption_round_keys[round_count]]
    for encryption_round_index in range(round_count - 1, 0, -1):
        word_0, word_1, word_2, word_3 = encryption_round_keys[encryption_round_index]
        decryption_round_keys.append(
            (
                (
                    DECRYPTION_TABLE_0[SBOX[(word_0 >> 24) & 0xFF]]
                    ^ DECRYPTION_TABLE_1[SBOX[(word_0 >> 16) & 0xFF]]
                    ^ DECRYPTION_TABLE_2[SBOX[(word_0 >> 8) & 0xFF]]
                    ^ DECRYPTION_TABLE_3[SBOX[word_0 & 0xFF]]
                ),
                (
                    DECRYPTION_TABLE_0[SBOX[(word_1 >> 24) & 0xFF]]
                    ^ DECRYPTION_TABLE_1[SBOX[(word_1 >> 16) & 0xFF]]
                    ^ DECRYPTION_TABLE_2[SBOX[(word_1 >> 8) & 0xFF]]
                    ^ DECRYPTION_TABLE_3[SBOX[word_1 & 0xFF]]
                ),
                (
                    DECRYPTION_TABLE_0[SBOX[(word_2 >> 24) & 0xFF]]
                    ^ DECRYPTION_TABLE_1[SBOX[(word_2 >> 16) & 0xFF]]
                    ^ DECRYPTION_TABLE_2[SBOX[(word_2 >> 8) & 0xFF]]
                    ^ DECRYPTION_TABLE_3[SBOX[word_2 & 0xFF]]
                ),
                (
                    DECRYPTION_TABLE_0[SBOX[(word_3 >> 24) & 0xFF]]
                    ^ DECRYPTION_TABLE_1[SBOX[(word_3 >> 16) & 0xFF]]
                    ^ DECRYPTION_TABLE_2[SBOX[(word_3 >> 8) & 0xFF]]
                    ^ DECRYPTION_TABLE_3[SBOX[word_3 & 0xFF]]
                ),
            )
        )
    decryption_round_keys.append(encryption_round_keys[0])
    return decryption_round_keys
