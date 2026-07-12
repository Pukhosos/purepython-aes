from purepython_aes.const import AES_BLOCK_SIZE


def xor(left: bytes, right: bytes) -> bytes:
    """XOR two equally sized byte strings."""

    return bytes(b0 ^ b1 for b0, b1 in zip(left, right, strict=True))


def split_into_blocks(data: bytes) -> tuple[bytes, ...]:
    """Split data into 16-byte blocks."""

    return tuple(
        data[block_start : (block_start + AES_BLOCK_SIZE)]
        for block_start in range(0, len(data), AES_BLOCK_SIZE)
    )
