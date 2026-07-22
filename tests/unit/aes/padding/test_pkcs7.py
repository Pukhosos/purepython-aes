from hypothesis import given, HealthCheck, settings
from hypothesis.strategies import binary
from pytest import mark, raises

from purepython_aes import Pkcs7Padding
from purepython_aes.const import AES_BLOCK_SIZE


@mark.quick
class TestPkcs7Padding:
    @staticmethod
    def test_pad_empty_data_adds_full_block(pkcs7: Pkcs7Padding) -> None:
        assert pkcs7.pad(bytes(0)) == bytes([AES_BLOCK_SIZE]) * AES_BLOCK_SIZE

    @staticmethod
    def test_pad_partial_block(pkcs7: Pkcs7Padding) -> None:
        assert pkcs7.pad(b'ABC') == b'ABC' + bytes([13]) * 13

    @staticmethod
    def test_pad_aligned_data_adds_full_block(pkcs7: Pkcs7Padding) -> None:
        data: bytes = bytes(range(AES_BLOCK_SIZE))
        assert pkcs7.pad(data) == data + bytes([AES_BLOCK_SIZE]) * AES_BLOCK_SIZE

    @staticmethod
    def test_unpad_rejects_empty_data(pkcs7: Pkcs7Padding) -> None:
        with raises(
            expected_exception=IndexError,
            match='index out of range',
        ):
            pkcs7.unpad(bytes(0))

    @staticmethod
    def test_unpad_rejects_unaligned_data(pkcs7: Pkcs7Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match='invalid PKCS#7 padding size',
        ):
            pkcs7.unpad(bytes(AES_BLOCK_SIZE - 1))

    @staticmethod
    def test_unpad_rejects_zero_padding_size(pkcs7: Pkcs7Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match='invalid PKCS#7 padding size',
        ):
            pkcs7.unpad(bytes(AES_BLOCK_SIZE - 1) + b'\x00')

    @staticmethod
    def test_unpad_rejects_padding_size_larger_than_block(pkcs7: Pkcs7Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match='invalid PKCS#7 padding size',
        ):
            pkcs7.unpad(bytes(AES_BLOCK_SIZE - 1) + bytes([AES_BLOCK_SIZE + 1]))

    @staticmethod
    def test_unpad_rejects_inconsistent_padding_bytes(pkcs7: Pkcs7Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match='invalid PKCS#7 padding bytes',
        ):
            pkcs7.unpad(b'A' * 13 + b'\x02\x03\x03')

    @staticmethod
    @given(data=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_unpad_inverts_pad(pkcs7: Pkcs7Padding, data: bytes) -> None:
        assert pkcs7.unpad(pkcs7.pad(data)) == data

    @staticmethod
    @given(data=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_padding_structure(pkcs7: Pkcs7Padding, data: bytes) -> None:
        padded_data: bytes = pkcs7.pad(data)
        padding_size: int = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        assert len(padded_data) % AES_BLOCK_SIZE == 0
        assert len(padded_data) == len(data) + padding_size
        assert padded_data[:len(data)] == data  # fmt: skip
        assert (
            padded_data[len(data):]  # fmt: skip
            == bytes([padding_size]) * padding_size
        )
