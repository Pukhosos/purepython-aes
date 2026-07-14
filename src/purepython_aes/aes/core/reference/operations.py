def galois256_multiply(left: int, right: int) -> int:
    """Multiply two bytes in the GF(2^8) finite field."""

    result: int = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        is_high_bit_set: bool = bool(left & 0x80)
        left = (left << 1) & 0xFF
        if is_high_bit_set:
            left ^= 0x1B
        right >>= 1
    return result


def xor_bytes(*bs: int) -> int:
    """XOR the supplied bytes."""

    result: int = 0
    for b in bs:
        result ^= b
    return result


def mix_column(b0: int, b1: int, b2: int, b3: int) -> tuple[int, int, int, int]:
    """Apply `MixColumns` to one AES state column."""

    return (
        xor_bytes(galois256_multiply(0x02, b0), galois256_multiply(0x03, b1), b2, b3),
        xor_bytes(b0, galois256_multiply(0x02, b1), galois256_multiply(0x03, b2), b3),
        xor_bytes(b0, b1, galois256_multiply(0x02, b2), galois256_multiply(0x03, b3)),
        xor_bytes(galois256_multiply(0x03, b0), b1, b2, galois256_multiply(0x02, b3)),
    )


def inverse_mix_column(b0: int, b1: int, b2: int, b3: int) -> tuple[int, int, int, int]:
    """Apply `InvMixColumns` to one AES state column."""

    return (
        xor_bytes(
            galois256_multiply(0x0E, b0),
            galois256_multiply(0x0B, b1),
            galois256_multiply(0x0D, b2),
            galois256_multiply(0x09, b3),
        ),
        xor_bytes(
            galois256_multiply(0x09, b0),
            galois256_multiply(0x0E, b1),
            galois256_multiply(0x0B, b2),
            galois256_multiply(0x0D, b3),
        ),
        xor_bytes(
            galois256_multiply(0x0D, b0),
            galois256_multiply(0x09, b1),
            galois256_multiply(0x0E, b2),
            galois256_multiply(0x0B, b3),
        ),
        xor_bytes(
            galois256_multiply(0x0B, b0),
            galois256_multiply(0x0D, b1),
            galois256_multiply(0x09, b2),
            galois256_multiply(0x0E, b3),
        ),
    )
