from purepython_aes.const import (
    AES_256_KEY_SIZE,
    AES_BLOCK_SIZE,
    AES_WORD_SIZE,
    ROUND_CONSTANTS,
    SBOX,
)


def expand_key(key: bytes, round_count: int) -> tuple[bytes, ...]:
    """Expand an AES key into one 16-byte key for every cipher round."""

    key_word_count: int = len(key) // AES_WORD_SIZE
    expanded_word_count: int = (AES_BLOCK_SIZE // AES_WORD_SIZE) * (round_count + 1)
    expanded_key: bytearray = bytearray(expanded_word_count * AES_WORD_SIZE)
    expanded_key[0 : len(key)] = key
    for word_index in range(key_word_count, expanded_word_count):
        previous_offset: int = (word_index - 1) * AES_WORD_SIZE
        b0: int = expanded_key[previous_offset]
        b1: int = expanded_key[previous_offset + 1]
        b2: int = expanded_key[previous_offset + 2]
        b3: int = expanded_key[previous_offset + 3]
        position_in_key: int = word_index % key_word_count
        if position_in_key == 0:
            round_constant_index: int = word_index // key_word_count
            b0, b1, b2, b3 = (
                SBOX[b1] ^ ROUND_CONSTANTS[round_constant_index],
                SBOX[b2],
                SBOX[b3],
                SBOX[b0],
            )
        else:
            if len(key) == AES_256_KEY_SIZE and position_in_key == 4:
                b0, b1, b2, b3 = SBOX[b0], SBOX[b1], SBOX[b2], SBOX[b3]
        source_offset: int = (word_index - key_word_count) * AES_WORD_SIZE
        destination_offset: int = word_index * AES_WORD_SIZE
        expanded_key[destination_offset] = expanded_key[source_offset] ^ b0
        expanded_key[destination_offset + 1] = expanded_key[source_offset + 1] ^ b1
        expanded_key[destination_offset + 2] = expanded_key[source_offset + 2] ^ b2
        expanded_key[destination_offset + 3] = expanded_key[source_offset + 3] ^ b3
    return tuple(
        bytes(expanded_key[offset : offset + AES_BLOCK_SIZE])
        for offset in range(0, len(expanded_key), AES_BLOCK_SIZE)
    )
