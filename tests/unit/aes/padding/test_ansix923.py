from re import escape

from hypothesis import given, HealthCheck, settings
from hypothesis.strategies import binary
from pytest import mark, raises

from purepython_aes import AnsiX923Padding
from purepython_aes.const import AES_BLOCK_SIZE


@mark.quick
class TestAnsiX923Padding:
    @staticmethod
    def test_pad_empty_data_adds_full_block(ansix923: AnsiX923Padding) -> None:
        padded_data: bytes = ansix923.pad(bytes(0))
        assert padded_data == bytes(AES_BLOCK_SIZE - 1) + bytes([AES_BLOCK_SIZE])

    @staticmethod
    def test_pad_partial_block(ansix923: AnsiX923Padding) -> None:
        padded_data: bytes = ansix923.pad(b'ABC')
        assert padded_data == b'ABC' + bytes(12) + b'\x0d'

    @staticmethod
    def test_pad_aligned_data_adds_full_block(ansix923: AnsiX923Padding) -> None:
        data: bytes = bytes(range(AES_BLOCK_SIZE))
        padded_data: bytes = ansix923.pad(data)
        assert padded_data == data + bytes(AES_BLOCK_SIZE - 1) + bytes([AES_BLOCK_SIZE])

    @staticmethod
    def test_unpad_rejects_empty_data(ansix923: AnsiX923Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('ANSI X9.23 padding expects non-empty data'),
        ):
            ansix923.unpad(bytes(0))

    @staticmethod
    def test_unpad_rejects_unaligned_data(ansix923: AnsiX923Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('invalid ANSI X9.23 padding size'),
        ):
            ansix923.unpad(bytes(AES_BLOCK_SIZE - 1))

    @staticmethod
    def test_unpad_rejects_zero_padding_size(ansix923: AnsiX923Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('invalid ANSI X9.23 padding size'),
        ):
            ansix923.unpad(bytes(AES_BLOCK_SIZE))

    @staticmethod
    def test_unpad_rejects_padding_size_larger_than_block(
        ansix923: AnsiX923Padding,
    ) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('invalid ANSI X9.23 padding size'),
        ):
            ansix923.unpad(bytes(AES_BLOCK_SIZE - 1) + bytes([AES_BLOCK_SIZE + 1]))

    @staticmethod
    def test_unpad_rejects_nonzero_fill_byte(ansix923: AnsiX923Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('invalid ANSI X9.23 padding bytes'),
        ):
            ansix923.unpad(b'A' * 13 + b'\x01\x00\x03')

    @staticmethod
    @given(data=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_unpad_inverts_pad(ansix923: AnsiX923Padding, data: bytes) -> None:
        assert ansix923.unpad(ansix923.pad(data)) == data

    @staticmethod
    @given(data=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_padding_structure(ansix923: AnsiX923Padding, data: bytes) -> None:
        padded_data: bytes = ansix923.pad(data)
        padding_size: int = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        assert len(padded_data) % AES_BLOCK_SIZE == 0
        assert len(padded_data) == len(data) + padding_size
        assert padded_data[: len(data)] == data
        assert padded_data[len(data) : (-1)] == bytes(padding_size - 1)
        assert padded_data[-1] == padding_size
