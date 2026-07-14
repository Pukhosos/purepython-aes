from pytest import mark

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
from purepython_aes.aes.core.reference.operations import galois256_multiply
from purepython_aes.const import INVERSE_SBOX, SBOX


@mark.quick
def test_encryption_table_0() -> None:
    assert ENCRYPTION_TABLE_0 == tuple(
        (
            (galois256_multiply(SBOX[value], 0x02) << 24)
            | (SBOX[value] << 16)
            | (SBOX[value] << 8)
            | galois256_multiply(SBOX[value], 0x03)
        )
        for value in range(0xFF + 1)
    )


@mark.quick
def test_encryption_table_1() -> None:
    assert ENCRYPTION_TABLE_1 == tuple(
        (
            (galois256_multiply(SBOX[value], 0x03) << 24)
            | (galois256_multiply(SBOX[value], 0x02) << 16)
            | (SBOX[value] << 8)
            | SBOX[value]
        )
        for value in range(0xFF + 1)
    )


@mark.quick
def test_encryption_table_2() -> None:
    assert ENCRYPTION_TABLE_2 == tuple(
        (
            (SBOX[value] << 24)
            | (galois256_multiply(SBOX[value], 0x03) << 16)
            | (galois256_multiply(SBOX[value], 0x02) << 8)
            | SBOX[value]
        )
        for value in range(0xFF + 1)
    )


@mark.quick
def test_encryption_table_3() -> None:
    assert ENCRYPTION_TABLE_3 == tuple(
        (
            (SBOX[value] << 24)
            | (SBOX[value] << 16)
            | (galois256_multiply(SBOX[value], 0x03) << 8)
            | galois256_multiply(SBOX[value], 0x02)
        )
        for value in range(0xFF + 1)
    )


@mark.quick
def test_decryption_table_0() -> None:
    assert DECRYPTION_TABLE_0 == tuple(
        (
            (galois256_multiply(INVERSE_SBOX[value], 0x0E) << 24)
            | (galois256_multiply(INVERSE_SBOX[value], 0x09) << 16)
            | (galois256_multiply(INVERSE_SBOX[value], 0x0D) << 8)
            | galois256_multiply(INVERSE_SBOX[value], 0x0B)
        )
        for value in range(0xFF + 1)
    )


@mark.quick
def test_decryption_table_1() -> None:
    assert DECRYPTION_TABLE_1 == tuple(
        (
            (galois256_multiply(INVERSE_SBOX[value], 0x0B) << 24)
            | (galois256_multiply(INVERSE_SBOX[value], 0x0E) << 16)
            | (galois256_multiply(INVERSE_SBOX[value], 0x09) << 8)
            | galois256_multiply(INVERSE_SBOX[value], 0x0D)
        )
        for value in range(0xFF + 1)
    )


@mark.quick
def test_decryption_table_2() -> None:
    assert DECRYPTION_TABLE_2 == tuple(
        (
            (galois256_multiply(INVERSE_SBOX[value], 0x0D) << 24)
            | (galois256_multiply(INVERSE_SBOX[value], 0x0B) << 16)
            | (galois256_multiply(INVERSE_SBOX[value], 0x0E) << 8)
            | galois256_multiply(INVERSE_SBOX[value], 0x09)
        )
        for value in range(0xFF + 1)
    )


@mark.quick
def test_decryption_table_3() -> None:
    assert DECRYPTION_TABLE_3 == tuple(
        (
            (galois256_multiply(INVERSE_SBOX[value], 0x09) << 24)
            | (galois256_multiply(INVERSE_SBOX[value], 0x0D) << 16)
            | (galois256_multiply(INVERSE_SBOX[value], 0x0B) << 8)
            | galois256_multiply(INVERSE_SBOX[value], 0x0E)
        )
        for value in range(0xFF + 1)
    )
