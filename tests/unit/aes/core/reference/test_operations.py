from itertools import product

from hypothesis import given
from pytest import mark

from purepython_aes.aes.core.reference.operations import (
    galois256_multiply,
    inverse_mix_column,
    mix_column,
    xor_bytes,
)
from tests.unit.aes.core.strategies import columns


@mark.quick
def xor_columns(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """XOR two four-byte columns."""

    return (
        left[0] ^ right[0],
        left[1] ^ right[1],
        left[2] ^ right[2],
        left[3] ^ right[3],
    )


@mark.quick
@mark.parametrize(
    ('left', 'right', 'expected'),
    (
        (0x00, 0x00, 0x00),
        (0x00, 0x01, 0x00),
        (0x01, 0x00, 0x00),
        (0x01, 0x01, 0x01),
        (0x57, 0x01, 0x57),
        (0x57, 0x02, 0xAE),
        (0x57, 0x04, 0x47),
        (0x57, 0x08, 0x8E),
        (0x57, 0x10, 0x07),
        (0x57, 0x13, 0xFE),
        (0x53, 0xCA, 0x01),
        (0xFF, 0xFF, 0x13),
        (0x80, 0x02, 0x1B),
        (0x80, 0x80, 0x9A),
    ),
)
def test_galois256_multiply_known_values(left: int, right: int, expected: int) -> None:
    assert galois256_multiply(left, right) == expected


@mark.quick
def test_galois256_multiply_zero_left() -> None:
    for n in range(0xFF + 1):
        assert galois256_multiply(0x00, n) == 0x00


@mark.quick
def test_galois256_multiply_zero_right() -> None:
    for n in range(0xFF + 1):
        assert galois256_multiply(n, 0x00) == 0x00


@mark.quick
def test_galois256_multiply_one_is_left_identity() -> None:
    for n in range(0xFF + 1):
        assert galois256_multiply(0x01, n) == n


@mark.quick
def test_galois256_multiply_one_is_right_identity() -> None:
    for n in range(0xFF + 1):
        assert galois256_multiply(n, 0x01) == n


@mark.quick
def test_galois256_multiply_is_commutative() -> None:
    for left, right in product(range(0xFF + 1), repeat=2):
        assert galois256_multiply(left, right) == galois256_multiply(right, left)


@mark.slow
def test_galois256_multiply_is_associative() -> None:
    for left, middle, right in product(range(0xFF + 1), repeat=3):
        assert galois256_multiply(
            galois256_multiply(left, middle), right
        ) == galois256_multiply(left, galois256_multiply(middle, right))


@mark.slow
def test_galois256_multiply_left_distributes_over_xor() -> None:
    for left, middle, right in product(range(0xFF + 1), repeat=3):
        assert galois256_multiply(left ^ middle, right) == (
            galois256_multiply(left, right) ^ galois256_multiply(middle, right)
        )


@mark.slow
def test_galois256_multiply_right_distributes_over_xor() -> None:
    for left, middle, right in product(range(0xFF + 1), repeat=3):
        assert galois256_multiply(left, middle ^ right) == (
            galois256_multiply(left, middle) ^ galois256_multiply(left, right)
        )


@mark.quick
@mark.parametrize(
    ('values', 'expected'),
    (
        ((), 0x00),
        ((0x00,), 0x00),
        ((0x57,), 0x57),
        ((0x57, 0x57), 0x00),
        ((0x57, 0x83), 0xD4),
        ((0xFF, 0x0F, 0xF0), 0x00),
        ((0x01, 0x02, 0x04, 0x08), 0x0F),
        ((0xDE, 0xAD, 0xBE, 0xEF), 0x22),
    ),
)
def test_xor_bytes_known_values(values: tuple[int, ...], expected: int) -> None:
    assert xor_bytes(*values) == expected


@mark.quick
def test_xor_bytes_value_with_itself_is_zero() -> None:
    for n in range(0xFF + 1):
        assert xor_bytes(n, n) == 0x00


@mark.quick
def test_xor_bytes_zero_left_is_identity() -> None:
    for n in range(0xFF + 1):
        assert xor_bytes(n, 0x00) == n


@mark.quick
def test_xor_bytes_zero_right_is_identity() -> None:
    for n in range(0xFF + 1):
        assert xor_bytes(0x00, n) == n


@mark.quick
def test_xor_bytes_is_commutative() -> None:
    for left, right in product(range(0xFF + 1), repeat=2):
        assert xor_bytes(left, right) == xor_bytes(right, left)


@mark.slow
def test_xor_bytes_is_associative() -> None:
    for left, middle, right in product(range(0xFF + 1), repeat=3):
        assert xor_bytes(xor_bytes(left, middle), right) == xor_bytes(
            left, xor_bytes(middle, right)
        )


@mark.quick
@given(left=columns, right=columns)
def test_mix_column_is_linear(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> None:
    xorred_mixed: tuple[int, int, int, int] = mix_column(*xor_columns(left, right))
    mixed_xorred: tuple[int, int, int, int] = xor_columns(
        mix_column(*left),
        mix_column(*right),
    )
    assert xorred_mixed == mixed_xorred


@mark.quick
@given(left=columns, right=columns)
def test_inverse_mix_column_is_linear(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> None:
    xorred_inverse_mixed: tuple[int, int, int, int] = inverse_mix_column(
        *xor_columns(left, right),
    )
    inverse_mixed_xorred: tuple[int, int, int, int] = xor_columns(
        inverse_mix_column(*left),
        inverse_mix_column(*right),
    )
    assert xorred_inverse_mixed == inverse_mixed_xorred


@mark.quick
@given(column=columns)
def test_inverse_mix_column_reverses_mix_column(
    column: tuple[int, int, int, int],
) -> None:
    assert inverse_mix_column(*mix_column(*column)) == column


@mark.quick
@given(column=columns)
def test_mix_column_reverses_inverse_mix_column(
    column: tuple[int, int, int, int],
) -> None:
    assert mix_column(*inverse_mix_column(*column)) == column
