from re import escape

from hypothesis import assume, given, HealthCheck, settings
from hypothesis.strategies import binary
from pytest import mark, raises

from purepython_aes.aes.padding import ZeroPadding
from purepython_aes.const import AES_BLOCK_SIZE
from tests.unit.aes.strategies import byte_values


@mark.quick
class TestZeroPadding:
    @staticmethod
    def test_pad_empty_data_returns_empty_data(zero: ZeroPadding) -> None:
        assert zero.pad(bytes(0)) == bytes(0)

    @staticmethod
    def test_pad_partial_block(zero: ZeroPadding) -> None:
        assert zero.pad(b'ABC') == b'ABC' + bytes(13)

    @staticmethod
    def test_pad_aligned_data_returns_data_unchanged(zero: ZeroPadding) -> None:
        data: bytes = bytes(range(AES_BLOCK_SIZE))
        assert zero.pad(data) == data

    @staticmethod
    def test_unpad_inverts_pad_empty_data(zero: ZeroPadding) -> None:
        assert zero.unpad(zero.pad(bytes(0))) == bytes(0)

    @staticmethod
    def test_unpad_removes_all_trailing_zeroes(zero: ZeroPadding) -> None:
        assert zero.unpad(b'ABC' + bytes(13)) == b'ABC'

    @staticmethod
    def test_unpad_all_zero_block_returns_empty_data(zero: ZeroPadding) -> None:
        assert zero.unpad(bytes(AES_BLOCK_SIZE)) == bytes(0)

    @staticmethod
    def test_trailing_plaintext_zeroes_are_not_preserved(zero: ZeroPadding) -> None:
        data: bytes = b'ABC\x00\x00'
        unpadded_data: bytes = zero.unpad(zero.pad(data))
        assert unpadded_data == b'ABC'
        assert unpadded_data != data

    @staticmethod
    def test_unpad_rejects_unaligned_data(zero: ZeroPadding) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('expected len(data) % 16 == 0, got 15'),
        ):
            zero.unpad(bytes(AES_BLOCK_SIZE - 1))

    @staticmethod
    @given(final_byte=byte_values, prefix=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_unpad_inverts_pad_not_zero_end(
        zero: ZeroPadding,
        prefix: bytes,
        final_byte: int,
    ) -> None:
        assume(final_byte != 0x00)
        data: bytes = prefix + bytes([final_byte])
        assert zero.unpad(zero.pad(data)) == data

    @staticmethod
    @given(data=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_padding_structure(zero: ZeroPadding, data: bytes) -> None:
        remainder_size: int = len(data) % AES_BLOCK_SIZE
        padding_size: int = 0
        if remainder_size != 0:
            padding_size = AES_BLOCK_SIZE - remainder_size
        padded_data: bytes = zero.pad(data)
        assert len(padded_data) % AES_BLOCK_SIZE == 0
        assert len(padded_data) == len(data) + padding_size
        assert padded_data[: len(data)] == data
        assert padded_data[len(data) :] == bytes(padding_size)
